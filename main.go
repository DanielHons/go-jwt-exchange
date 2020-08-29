package main

import (
	jwtexchange "github.com/DanielHons/go-jwt-exchange/jwt_exchange"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	jx := jwtexchange.TokenExchangerConfigFromEnv()
	jx.ClaimsMapper = rewriteClaims
	jx.IncomingTokenHeader = jwtexchange.PlainTokenHeader(os.Getenv("TOKEN_HEADER_IN"))
	http.HandleFunc("/", jx.ProxyHandler())
	log.Fatal(http.ListenAndServe(":"+jx.BindPort, nil))
}

// CUSTOM

const internalTokenLifetime = 3 // seconds

func rewriteClaims(claims jwt.MapClaims) jwt.Claims {
	username := claims["sub"].(string)
	unix := time.Now().Unix()
	newClaims := jwt.StandardClaims{
		Subject:   username,
		IssuedAt:  unix,
		ExpiresAt: unix + internalTokenLifetime,
		Audience:  "postgraphile",
	}
	return newClaims
}
