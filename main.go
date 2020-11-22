package main

import (
	"github.com/DanielHons/go-jwt-exchange/jwt_exchange"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const k_bindAddress = "BIND_ADDRESS"
const k_jwtSecret = "JWT_SECRET"
const k_jwtCreateTTL = "OUTGOING_TOKEN_TTL_SEC"
const k_jwksUrl = "JWKS_URL"
const k_tokenHeaderIn = "TOKEN_HEADER_IN"
const k_proxyTargetUrl = "TARGET_URL"
const k_tokenHeaderOut = "TOKEN_HEADER_OUT"

const authorization = "Authorization"
const defaultBindAddress = "0.0.0.0:9002"
const bearerPrefix = "Bearer "

const defaultTokenLifetimeSeconds = 3

func main() {

	jwksCache := jwt_exchange.StartNewJwkCache(os.Getenv(k_jwksUrl),
		24*time.Hour, true,
	)

	handler := jwt_exchange.TokenExchangeHandler{
		ClaimsExtractor: jwt_exchange.JwksClaimsExtractor{
			Validator: &jwksCache,
			TokenReader: jwt_exchange.HeaderTokenReader{
				HeaderName: os.Getenv(k_tokenHeaderIn),
				TrimPrefix: true,
				Prefix:     bearerPrefix,
			},
		},
		ClaimsMapper: jwt_exchange.GenericClaimsMapper{
			TokenTTL: readTokenLifetimeFromEnv(),
			Audience: "",
		},
		TokenCreator: jwt_exchange.JwtCreator_HS256{
			JwtSecret: []byte(os.Getenv(k_jwtSecret)),
		},
		HeaderTokenWriter: jwt_exchange.HeaderTokenWriter{
			HeaderName: getEnvOrDefault(k_tokenHeaderOut, authorization),
			Prefix:     bearerPrefix,
		},
		Director:        jwt_exchange.DefaultProxyDirector(os.Getenv(k_proxyTargetUrl)),
		RejectOnNoToken: true,
	}

	http.HandleFunc("/", handler.ProxyHandler())
	log.Fatal(http.ListenAndServe(getEnvOrDefault(k_bindAddress, defaultBindAddress), nil))
}

func getEnvOrDefault(key string, defaultValue string) string {
	env := os.Getenv(key)
	if len(env) == 0 {
		return defaultValue
	}
	return env
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
