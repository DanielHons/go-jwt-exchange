package jwt_exchange

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const bearerPrefix = "Bearer "
const authorization = "Authorization"

type TokenExchangeConfig struct {
	TokenReader             TokenReader
	ReplacementTokenCreator TokenCreator
	IncomingTokenHeader     string
	OutgoingTokenHeader     string
	OutgoingTokenPrefix     string
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

type JwtCreator_HS256 struct {
	ClaimsMapper func(claims jwt.MapClaims) jwt.Claims
	JwtSecret    []byte
}

func (j JwtCreator_HS256) createToken(originalClaims jwt.MapClaims) (string, error) {
	internalToken, signingErr := jwt.NewWithClaims(jwt.SigningMethodHS256,
		j.ClaimsMapper(originalClaims)).SignedString(j.JwtSecret)
	if signingErr != nil {
		return "", signingErr
	}
	return internalToken, nil
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
		log.Fatal("Could not load JWKS to start working:", err)
	}
	return &cache
}

func NewTokenExchange(targetUrl string, jwksUrl string, jwtSigningSecret []byte) TokenExchangeConfig {
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
