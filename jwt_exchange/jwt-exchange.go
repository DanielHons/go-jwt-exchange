package jwt_exchange

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

func DefaultProxyDirector(rawUrl string) func(req *http.Request) {
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

type ClaimsMapper interface {
	MapClaims(claims jwt.MapClaims) (jwt.Claims, error)
}

type GenericClaimsMapper struct {
	TokenTTL int64
	Audience string
}

type StringExtractingClaimsMapper struct {
	TokenTTL    int64
	Audience    string
	Extractor   func(claims jwt.MapClaims) string
	OutClaimKey string
}

// Implement ClaimsMapper interface
func (secm StringExtractingClaimsMapper) MapClaims(inClaims jwt.MapClaims) (jwt.Claims, error) {
	outClaims := DefaultClaims(inClaims["sub"].(string), secm.TokenTTL, secm.Audience)
	outClaims[secm.OutClaimKey] = secm.Extractor(inClaims)
	return outClaims, nil
}

// Take subject from incoming claim, override iat,nbf,exp and potentially aud
func DefaultClaims(sub string, ttl int64, aud string) jwt.MapClaims {
	unix := time.Now().Unix()
	mapClaims := jwt.MapClaims{}
	mapClaims["sub"] = sub
	mapClaims["iat"] = unix
	mapClaims["nbf"] = unix
	mapClaims["exp"] = unix + ttl
	if len(aud) > 0 {
		mapClaims["aud"] = aud
	}

	return mapClaims
}

func (gtm GenericClaimsMapper) MapClaims(claims jwt.MapClaims) (jwt.Claims, error) {
	return DefaultClaims(claims["sub"].(string), gtm.TokenTTL, gtm.Audience), nil
}

type TokenExchangeConfig struct {
	ClaimsExtractor         ClaimsExtractor
	ReplacementTokenCreator TokenCreator
	OutgoingTokenHeader     string
	OutgoingTokenPrefix     string
	ProxyBindAddress        string
	TargetUrl               string
}

type TokenHeaderField struct {
	header string
	bearer bool
}

// validates the incoming token and extracts MapClaims
type TokenValidator interface {
	Validate(token string) (jwt.MapClaims, error)
}

// Creates the outgoing token from provided claims
type TokenCreator interface {
	CreateToken(orginalClaims jwt.Claims) (string, error)
}

type GenericTokenCreator struct {
	CreationFunc func(orginalClaims jwt.MapClaims) (string, error)
}

func (g GenericTokenCreator) CreateToken(orginalClaims jwt.MapClaims) (string, error) {
	return g.CreationFunc(orginalClaims)
}

type JwtCreator_HS256 struct {
	JwtSecret []byte
}

func (j JwtCreator_HS256) CreateToken(inputClaims jwt.Claims) (string, error) {
	internalToken, signingErr := jwt.NewWithClaims(jwt.SigningMethodHS256,
		inputClaims).SignedString(j.JwtSecret)
	if signingErr != nil {
		return "", signingErr
	}
	return internalToken, nil
}

type ClaimsExtractor interface {
	Extract(req *http.Request) (jwt.MapClaims, error)
}

type TokenReader interface {
	Read(re *http.Request) string
}

type TokenWriter interface {
	Write(w http.ResponseWriter)
}

type HeaderTokenWriter struct {
	HeaderName string
	Prefix     string
}

func (htw HeaderTokenWriter) Write(r *http.Request, token string) {
	newToken := htw.Prefix + token
	r.Header.Set(htw.HeaderName, newToken)
}

type HeaderTokenReader struct {
	HeaderName string
	TrimPrefix bool
	Prefix     string
}

func (htr HeaderTokenReader) Read(r *http.Request) string {
	tokenHeader := r.Header.Get(htr.HeaderName)
	if htr.TrimPrefix && strings.HasPrefix(tokenHeader, htr.Prefix) {
		tokenHeader = strings.TrimPrefix(tokenHeader, htr.Prefix)
	}
	r.Header.Set(htr.HeaderName, "") // Do not forward
	return tokenHeader
}

type JwksClaimsExtractor struct {
	Validator   TokenValidator
	TokenReader TokenReader
}

func (extractor JwksClaimsExtractor) Extract(r *http.Request) (jwt.MapClaims, error) {
	return extractor.Validator.Validate(extractor.TokenReader.Read(r))
}

type TokenExchangeHandler struct {
	ClaimsExtractor   ClaimsExtractor
	ClaimsMapper      ClaimsMapper
	TokenCreator      TokenCreator
	HeaderTokenWriter HeaderTokenWriter
	Director          func(r *http.Request)
	RejectOnNoToken   bool
}

func (teh TokenExchangeHandler) createToken(r *http.Request) (string, error) {
	originalClaims, err := teh.ClaimsExtractor.Extract(r)
	if err != nil {
		return "", err
	}
	newClaims, err := teh.ClaimsMapper.MapClaims(originalClaims)
	if err != nil {
		return "", err
	}
	return teh.TokenCreator.CreateToken(newClaims)
}

func (teh TokenExchangeHandler) ProxyHandler() func(w http.ResponseWriter, r *http.Request) {
	proxy := &httputil.ReverseProxy{Director: teh.Director}
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := teh.createToken(r)
		if err != nil && teh.RejectOnNoToken {
			w.WriteHeader(401)
			return
		} else {
			teh.HeaderTokenWriter.Write(r, token)
			proxy.ServeHTTP(w, r)
		}
	}
}
