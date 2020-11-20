package jwt_exchange

import (
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

type ClaimsMapper interface {
	mapClaims(claims jwt.MapClaims) (jwt.MapClaims, error)
}

type GenericClaimsMapper struct {
	TokenTTL int64
	Audience string
}

func (gtm GenericClaimsMapper) mapClaims(claims jwt.MapClaims) (jwt.MapClaims, error) {
	unix := time.Now().Unix()
	mapClaims := jwt.MapClaims{}
	mapClaims["sub"] = claims["sub"].(string)
	mapClaims["iat"] = unix
	mapClaims["nbf"] = unix
	mapClaims["exp"] = unix + gtm.TokenTTL
	if len(gtm.Audience) > 0 {
		mapClaims["aud"] = gtm.Audience
	}

	return mapClaims, nil
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
	CreateToken(orginalClaims jwt.MapClaims) (string, error)
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

func (j JwtCreator_HS256) CreateToken(inputClaims jwt.MapClaims) (string, error) {
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
	newClaims, err := teh.ClaimsMapper.mapClaims(originalClaims)
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
