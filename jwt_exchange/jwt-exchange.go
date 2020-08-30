package jwt_exchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const bearerPrefix = "Bearer "
const authorization = "Authorization"

// Environment variable keys
const k_jwksUrl = "JWKS_URL"
const k_jwtSecret = "JWT_SECRET"
const k_bindAddress = "BIND_ADDRESS"
const k_proxyTargetUrl = "TARGET_URL"
const k_tokenHeaderIn = "TOKEN_HEADER_IN"
const k_tokenHeaderOut = "TOKEN_HEADER_OUT"
const k_jwtCreateAudience = "OUTGOING_AUDIENCE"
const k_jwtCreateTTL = "OUTGOING_TOKEN_TTL_SEC"

// Default values
const defaultBindAddress = "0.0.0.0:9002"
const defaultTokenLifetimeSeconds = 3

type ClaimsMapper func(claims jwt.MapClaims) jwt.Claims

type TokenExchangeProxy struct {
	Config   TokenExchangeConfig
	Director func(r *http.Request)
}

func NewTokenExchangeProxy(
	config TokenExchangeConfig) TokenExchangeProxy {
	return TokenExchangeProxy{
		Config: config, Director: defaultDirector(config.TargetUrl)}
}

func NewProxy() TokenExchangeProxy {
	targetUrl := os.Getenv(k_proxyTargetUrl)
	return NewTokenExchangeProxy(loadConfigFromEnv(targetUrl))
}

func (proxy TokenExchangeProxy) Start(creator TokenCreator) {
	//http.HandleFunc("/tkn/health", func(writer http.ResponseWriter, request *http.Request) {
	//	writer.WriteHeader(200)
	//	writer.Write([]byte(`{"status":"up"}`))
	//})
	proxy.Config.ReplacementTokenCreator = creator

	http.HandleFunc("/", proxy.ProxyHandler())
	log.Fatal(http.ListenAndServe(proxy.Config.ProxyBindAddress, nil))
}

func (px TokenExchangeProxy) ProxyHandler() func(w http.ResponseWriter, r *http.Request) {
	proxy := &httputil.ReverseProxy{Director: px.Director}
	return func(w http.ResponseWriter, r *http.Request) {
		err := px.Config.ExchangeToken(r)
		if err != nil {
			log.Println("Authentication failed:", err)
			w.WriteHeader(401)
			return
		}
		proxy.ServeHTTP(w, r)
	}
}

func readTokenLifetimeFromEnv() int64 {
	envLifetime := os.Getenv(k_jwtCreateTTL)
	if len(envLifetime) == 0 {
		return defaultTokenLifetimeSeconds
	}
	atoi, err := strconv.Atoi(envLifetime)
	if err != nil {
		log.Println("Could not read " + k_jwtCreateTTL + ", " +
			"using " + strconv.Itoa(defaultTokenLifetimeSeconds))
		return defaultTokenLifetimeSeconds
	}
	return int64(atoi)
}

type TokenExchangeConfig struct {
	TokenReader             TokenReader
	ReplacementTokenCreator TokenCreator
	IncomingTokenHeader     string
	OutgoingTokenHeader     string
	OutgoingTokenPrefix     string
	ProxyBindAddress        string
	TargetUrl               string
}

func loadConfigFromEnv(targetUrl string) TokenExchangeConfig {
	exchange := NewTokenExchange(
		os.Getenv(k_jwksUrl),
		[]byte(os.Getenv(k_jwtSecret)))
	exchange.IncomingTokenHeader = os.Getenv(k_tokenHeaderIn)
	exchange.OutgoingTokenHeader = os.Getenv(k_tokenHeaderOut)
	exchange.IncomingTokenHeader = os.Getenv(k_tokenHeaderIn)
	exchange.ProxyBindAddress = getEnvOrDefault(k_bindAddress, defaultBindAddress)
	exchange.TargetUrl = os.Getenv(k_proxyTargetUrl)
	exchange.ReplacementTokenCreator = DefaultJwtCreator(func(claims jwt.MapClaims) jwt.Claims {
		return claims
	})
	return exchange
}

type TokenHeaderField struct {
	header string
	bearer bool
}

// validates the incoming token and extracts MapClaims
type TokenReader interface {
	validate(token string) (jwt.MapClaims, error)
}

// Creates the outgoing token from provided claims
type TokenCreator interface {
	createToken(orginalClaims jwt.MapClaims) (string, error)
}

type GenericTokenCreator struct {
	CreationFunc func(orginalClaims jwt.MapClaims) (string, error)
}

func (g GenericTokenCreator) createToken(orginalClaims jwt.MapClaims) (string, error) {
	return g.CreationFunc(orginalClaims)
}

type JwtCreator_HS256 struct {
	ClaimsMapper func(claims jwt.MapClaims) jwt.Claims
	JwtSecret    []byte
	TokenTTL     int64
	Audience     string
	SetDefaults  bool
}

func DefaultJwtCreator(mapper func(claims jwt.MapClaims) jwt.Claims) TokenCreator {
	return JwtCreator_HS256{
		ClaimsMapper: mapper,
		JwtSecret:    []byte(os.Getenv(k_jwtSecret)),
		TokenTTL:     readTokenLifetimeFromEnv(),
		Audience:     os.Getenv(k_jwtCreateAudience),
		SetDefaults:  true,
	}
}

func (j JwtCreator_HS256) createToken(originalClaims jwt.MapClaims) (string, error) {
	var inputClaims jwt.MapClaims
	if j.SetDefaults {
		defaults, err := j.updateDefaults(originalClaims)
		if err != nil {
			return "", err
		}
		inputClaims = defaults
	} else {
		inputClaims = originalClaims
	}

	internalToken, signingErr := jwt.NewWithClaims(jwt.SigningMethodHS256,
		j.ClaimsMapper(inputClaims)).SignedString(j.JwtSecret)
	if signingErr != nil {
		return "", signingErr
	}
	return internalToken, nil
}

func (j JwtCreator_HS256) updateDefaults(originalClaims jwt.MapClaims) (jwt.MapClaims, error) {
	resultClaims := jwt.MapClaims{}
	marshal, err := json.Marshal(originalClaims)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(marshal, &resultClaims)
	if err != nil {
		return nil, err
	}
	unix := time.Now().Unix()

	resultClaims["iat"] = unix
	resultClaims["nbf"] = unix
	resultClaims["exp"] = unix + j.TokenTTL
	resultClaims["aud"] = j.Audience
	return resultClaims, nil
}

type jwksCache struct {
	JwksUrl             string
	jwksMutex           sync.Mutex
	JwksRefreshInterval time.Duration
	lastRefresh         int64
	jwkSet              *jwk.Set
}

func NewJwksCache(jwksUrl string, refreshInterval time.Duration) *jwksCache {
	cache := jwksCache{
		JwksUrl:             jwksUrl,
		JwksRefreshInterval: refreshInterval,
		lastRefresh:         0,
		jwkSet:              nil,
	}
	err := cache.reloadJwks()
	if err != nil {
		log.Fatal("Could not load JWKS to Start working:", err)
	}
	return &cache
}

func NewTokenExchange(jwksUrl string, jwtSigningSecret []byte) TokenExchangeConfig {
	return TokenExchangeConfig{
		TokenReader: NewJwksCache(jwksUrl, 24*time.Second),
		ReplacementTokenCreator: JwtCreator_HS256{
			ClaimsMapper: defaultClaimsMapper,
			JwtSecret:    jwtSigningSecret,
		},
		// The default header configuration is to search for header "Authorization" with Content "Bearer "+$token
		IncomingTokenHeader: authorization,
		// This configuration can also be written as follows:
		OutgoingTokenHeader: authorization,
		OutgoingTokenPrefix: bearerPrefix,
	}
}

func defaultClaimsMapper(claims jwt.MapClaims) jwt.Claims {
	return claims
}

func (c *jwksCache) refreshIfRequired() {
	if c.lastRefresh+c.JwksRefreshInterval.Milliseconds()/1000 < time.Now().Unix() {
		go func() {
			// this can wait till the request was handled
			defer c.jwksMutex.Unlock()
			_ = c.reloadJwks() //fire and forget
		}()
	}
}

func (c *jwksCache) reloadJwks() error {
	log.Println("Refreshing jwk set from " + c.JwksUrl)
	set, err := jwk.FetchHTTP(c.JwksUrl)
	if err != nil {
		log.Println("ERROR fetching jwk set from " + c.JwksUrl)
		return err
	}
	c.jwkSet = set
	c.lastRefresh = time.Now().Unix()
	log.Println("jwk set refreshedL")
	return nil
}

func (c *jwksCache) getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := c.jwkSet.LookupKeyID(keyID); len(key) == 1 {
		var k interface{}
		err := key[0].Raw(&k)
		return k, err
	}

	return nil, fmt.Errorf("unable to find key %q", keyID)
}

func (c *jwksCache) validate(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, c.getKey)
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	return claims, nil
}

func (config *TokenExchangeConfig) ExchangeToken(r *http.Request) error {
	// Extract claims from
	token := extractTokenFromIncomingRequest(r, config.IncomingTokenHeader)
	if len(token) == 0 {
		return errors.New("No token provided")
	}

	claims, err := config.TokenReader.validate(token)
	if err != nil {
		return err
	}
	newToken, err := config.ReplacementTokenCreator.createToken(claims)
	if err != nil {
		return err
	}

	config.setInternalTokenToRequest(r, newToken, config.OutgoingTokenHeader)
	return nil
}

func (c TokenExchangeConfig) setInternalTokenToRequest(r *http.Request, newToken string, headerKey string) {
	newToken = c.OutgoingTokenPrefix + newToken
	r.Header.Set(headerKey, newToken)
}

func extractTokenFromIncomingRequest(r *http.Request, headerKey string) string {
	tokenHeader := r.Header.Get(headerKey)
	if strings.HasPrefix(tokenHeader, bearerPrefix) {
		tokenHeader = strings.TrimPrefix(tokenHeader, bearerPrefix)
	}
	r.Header.Set(headerKey, "") // Do not forward
	return tokenHeader
}

// UTILS
func defaultDirector(rawUrl string) func(req *http.Request) {
	targetUrl := rawUrl
	origin, _ := url.Parse(targetUrl)
	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = extractProtocol(targetUrl)
		req.URL.Host = origin.Host
	}
	return director
}

func extractProtocol(targetUrl string) string {
	return strings.Split(targetUrl, "://")[0]
}

func getEnvOrDefault(key string, defaultValue string) string {
	env := os.Getenv(key)
	if len(env) == 0 {
		return defaultValue
	}
	return env
}

func rewriteClaims(claims jwt.MapClaims, tokenLifetime int64, audience string) jwt.Claims {
	unix := time.Now().Unix()
	newClaims := jwt.StandardClaims{
		Subject:   claims["sub"].(string),
		IssuedAt:  unix,
		NotBefore: unix,
		ExpiresAt: unix + tokenLifetime,
		Audience:  audience,
	}
	return newClaims
}
