package jwt_exchange

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"sync"
	"time"
)

type JwksCache struct {
	JwksUrl             string
	jwksMutex           sync.Mutex
	JwksRefreshInterval time.Duration
	lastRefresh         int64
	jwkSet              *jwk.Set
}

func (c *JwksCache) ReloadJwks() error {
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

func (c *JwksCache) getKey(token *jwt.Token) (interface{}, error) {
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

func (c *JwksCache) Validate(tokenString string) (jwt.MapClaims, error) {
	c.refreshIfRequired()
	token, err := jwt.Parse(tokenString, c.getKey)
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	return claims, nil
}

func (c *JwksCache) refreshIfRequired() {
	if c.lastRefresh+c.JwksRefreshInterval.Milliseconds()/1000 < time.Now().Unix() {
		log.Println("Refreshing outdated JWKS")
		go func() {
			// this can wait till the request was handled
			c.jwksMutex.Lock()
			defer c.jwksMutex.Unlock()
			_ = c.ReloadJwks() //fire and forget
		}()
	}
}
