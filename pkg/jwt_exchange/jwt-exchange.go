package jwt_exchange

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
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

type FancyClaimsMapper struct {
	TokenTTL     int64
	Audience     string
	StaticClaims map[string]string
	MappedClaims map[string]string
}

// Take subject from incoming claim, override iat,nbf,exp and potentially aud
func defaultClaims(ttl int64, aud string) jwt.MapClaims {
	unix := time.Now().Unix()
	mapClaims := jwt.MapClaims{}
	mapClaims["iat"] = unix
	mapClaims["nbf"] = unix
	mapClaims["exp"] = unix + ttl
	if len(aud) > 0 {
		mapClaims["aud"] = aud
	}

	return mapClaims
}

func (fcm FancyClaimsMapper) MapClaims(claims jwt.MapClaims) (jwt.Claims, error) {
	outClaims := defaultClaims(fcm.TokenTTL, fcm.Audience)
	for r, s := range fcm.StaticClaims {
		outClaims[r] = s
	}
	for r, s := range fcm.MappedClaims {
		outClaims[r] = claims[s]
	}
	return outClaims, nil
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

type TokenExchangeHandler struct {
	ClaimsExtractor   ClaimsExtractor
	ClaimsMapper      ClaimsMapper
	TokenCreator      TokenCreator
	HeaderTokenWriter HeaderTokenWriter
	Director          func(r *http.Request)
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
		if err != nil {
			log.Println("auth failed : ", err)
			w.WriteHeader(401)
			return
		} else {
			teh.HeaderTokenWriter.Write(r, token)
			proxy.ServeHTTP(w, r)
		}
	}
}

type BearerJwtClaimsExtractor struct {
	HeaderName string
	TrimPrefix bool
	Prefix     string
	Audience   string
	Validator  TokenValidator
}

func (ce *BearerJwtClaimsExtractor) Extract(r *http.Request) (jwt.MapClaims, error) {
	tokenString := r.Header.Get(ce.HeaderName)
	if ce.TrimPrefix && strings.HasPrefix(tokenString, ce.Prefix) {
		tokenString = strings.TrimPrefix(tokenString, ce.Prefix)
	}
	r.Header.Set(ce.HeaderName, "") // Do not forward

	validate, err := ce.Validator.Validate(tokenString)
	if err != nil {
		return nil, err
	}

	err = ce.checkAudience(validate["aud"])
	if err != nil {
		return nil, err
	}

	return validate, nil
}

func (ce *BearerJwtClaimsExtractor) checkAudience(givenAud interface{}) error {
	switch x := givenAud.(type) {
	case []interface{}:
		for _, i := range x {
			if i == ce.Audience {
				return nil // required audience was found
			}
			return errors.New("required audience not found in given token")
		}
	case interface{}:
		if x != ce.Audience {
			return errors.New("wrong audience in given token")
		}
	default:
		fmt.Printf("Unsupported type for audience: %T\n", x)
		return errors.New("unsupported type for audience")
	}
	return errors.New("missing audience")
}
