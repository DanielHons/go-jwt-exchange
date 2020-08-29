package main

import (
	jwtexchange "github.com/DanielHons/go-jwt-exchange/jwt_exchange"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable keys
const k_jwksUrl = "JWKS_URL"
const k_jwtSecret = "JWT_SECRET"
const k_bindAddress = "BIND_ADDRESS"
const k_proxyTargetUrl = "TARGET_URL"
const k_tokenHeaderIn = "TOKEN_HEADER_IN"
const k_tokenHeaderOut = "TOKEN_HEADER_OUT"
const k_outgoingClaimAudience = "OUTGOING_AUDIENCE"
const k_internalTokenLifetimeSeconds = "OUTGOING_TOKEN_TTL_SEC"

// Default values
const defaultBindAddress = "0.0.0.0:9002"
const defaultTokenLifetimeSeconds = 3

// Outgoing token creation
var audience string
var tokenLifetime int64
var targetUrl string

func main() {
	targetUrl = os.Getenv(k_proxyTargetUrl)
	audience = os.Getenv(k_outgoingClaimAudience)
	configureTokenLifetime()
	jx := createConfig()

	http.HandleFunc("/", ProxyHandler(jx))
	log.Fatal(http.ListenAndServe(getEnvOrDefault(k_bindAddress, defaultBindAddress), nil))
}

func ProxyHandler(jx jwtexchange.TokenExchangeConfig) func(w http.ResponseWriter, r *http.Request) {
	proxy := &httputil.ReverseProxy{Director: requestDirector(targetUrl)}
	return func(w http.ResponseWriter, r *http.Request) {
		err := jx.ExchangeToken(r)
		if err != nil {
			log.Println("Authentication failed:", err)
			w.WriteHeader(401)
			w.Write([]byte(err.Error()))
			return
		}
		proxy.ServeHTTP(w, r)
	}
}

func configureTokenLifetime() {
	envLifetime := os.Getenv(k_internalTokenLifetimeSeconds)
	if len(envLifetime) == 0 {
		tokenLifetime = defaultTokenLifetimeSeconds
		return
	}
	atoi, err := strconv.Atoi(envLifetime)
	if err != nil {
		log.Println("Could not read " + k_internalTokenLifetimeSeconds + ", " +
			"using " + strconv.Itoa(defaultTokenLifetimeSeconds))
		tokenLifetime = defaultTokenLifetimeSeconds
		return
	}
	tokenLifetime = int64(atoi)
}

func rewriteClaims(claims jwt.MapClaims) jwt.Claims {
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

func createConfig() jwtexchange.TokenExchangeConfig {
	exchange := jwtexchange.NewTokenExchange(
		targetUrl,
		os.Getenv(k_jwksUrl),
		[]byte(os.Getenv(k_jwtSecret)))
	exchange.IncomingTokenHeader = os.Getenv(k_tokenHeaderIn)
	exchange.OutgoingTokenHeader = os.Getenv(k_tokenHeaderOut)
	exchange.IncomingTokenHeader = os.Getenv(k_tokenHeaderIn)
	exchange.ReplacementTokenCreator = jwtexchange.JwtCreator_HS256{
		ClaimsMapper: rewriteClaims,
		JwtSecret:    []byte(os.Getenv(k_jwtSecret)),
	}
	return exchange

}

func getEnvOrDefault(key string, defaultValue string) string {
	env := os.Getenv(key)
	if len(env) == 0 {
		return defaultValue
	}
	return env
}

func requestDirector(rawUrl string) func(req *http.Request) {
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
