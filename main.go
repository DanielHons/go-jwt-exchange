package main

import (
	jwt_exchange "github.com/DanielHons/go-jwt-exchange/jwt-exchange"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"time"
)

func main() {
	jx := jwt_exchange.TokenExchangerConfigFromEnv()
	jx.ClaimsMapper = rewriteClaims
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
