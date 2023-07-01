package jwt_exchange

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"time"
)

type jwksCache struct {
	JwksUrl     string
	lastRefresh int64
	jwkSet      jwk.Set
}

func StartNewJwkCache(jwksUrl string, refreshInterval time.Duration, stopOnError bool) jwksCache {
	cache := jwksCache{
		JwksUrl:     jwksUrl,
		lastRefresh: 0,
		jwkSet:      nil,
	}
	err := cache.reloadInner()
	if err != nil {
		const msg = "JWK set could not be initially loaded - no token can be verified"
		if stopOnError {
			log.Fatal(msg)
		} else {
			log.Println(msg)
		}
	}
	refreshTicker := time.NewTicker(refreshInterval)

	go func() {
		for {
			<-refreshTicker.C
			cache.reload()
		}
	}()

	return cache
}

func (cache jwksCache) reload() {
	err := cache.reloadInner()
	if err != nil {
		log.Println("error reloading jwks: " + err.Error())
	}
}

func (cache *jwksCache) reloadInner() error {
	set, err := jwk.Fetch(context.TODO(), cache.JwksUrl)
	if err != nil {
		return err
	}
	cache.jwkSet = set
	cache.lastRefresh = time.Now().Unix()
	log.Println("successfully reloaded JWK set from " + cache.JwksUrl)
	return nil
}

func (cache *jwksCache) getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	key, hasMore := cache.jwkSet.LookupKeyID(keyID)
	if hasMore {
		log.Println("key with kid not unuque: " + keyID)
	}

	if key == nil {
		return nil, fmt.Errorf("unable to find key %q", keyID)
	}

	var k interface{}
	err := key.Raw(&k)
	return k, err
}

func (cache *jwksCache) Validate(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, cache.getKey)
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	return claims, nil
}
