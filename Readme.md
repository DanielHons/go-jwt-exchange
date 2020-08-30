# go jwt exchange
A lightweight webproxy to exchange an authorization token.

##### Develop
![Go](https://github.com/DanielHons/go-jwt-exchange/workflows/Go/badge.svg?branch=develop)


#### Use
The desired usecase is to translate an incoming Jason Web Token (JWT) into any outgoing authentication token (which does not have to be a JWT) before passing the request to a backend service.
This is handy in combination with tools like [PostgREST](http://postgrest.org/en/v7.0.0/) or [postgraphile](https://www.graphile.org/postgraphile/).

```go
package main

import (
	jwtexchange "github.com/DanielHons/go-jwt-exchange/jwt_exchange"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)



func main() {
	proxy := jwtexchange.NewProxy()
	jwtCreator := jwtexchange.DefaultJwtCreator(func(claims jwt.MapClaims) jwt.Claims {
        // Customize the claims
		claims["user_role"] = "admin"
		return claims
	})
	proxy.Start(jwtCreator)

}
``` 

The proxy contains a configuration with default values read from environment variables but can be changed programatically as well, like

```go
proxy.Config.OutgoingTokenPrefix="" // Do not use "Bearer " prefix
```

### Configure the token exchange

| Config Property            | Meaning                                                          | Example                         | Environment variable  | Default  |     
|----------------------------|------------------------------------------------------------------| --------------------------------|-----------------------| ----------------------|     
| `TargetUrl`                |  Where to pass requests with the new token to                    |  "http://internal-service:1234" | `TARGET_URL`          |           |     
| `IncomingTokenHeader`      |  Key of the header to look for the incoming token                |  "X_AUTH_TOKEN"                 | `TOKEN_HEADER_IN`     | "Authorization"      |     
| `OutgoingTokenHeader`      |  Key of the header to set the outgoing  token                    |  "X_AUTH_TOKEN"                 | `TOKEN_HEADER_OUT`    | "Authorization"    |     
| `OutgoingTokenPrefix`      |  A prefix to set before the outgoing token (usually "Bearer ")   |  "Bearer "                      |                       | "Bearer "                      |     
| `ProxyBindAddress`         |  Where to pass requests with the new token to                    |  "http://internal-service:1234" | `BIND_ADDRESS`        | "0.0.0.0:9002"        |     

 
#### Creating custom tokens
If the outgoing token is not a JWT (or is fetched from another api instead assembling it in this exchage) you can start the proxy as follows.
The token will be injected in the configured header with the configured prefix.

```go
	proxy.Start(jwtexchange.GenericTokenCreator{CreationFunc: func(claims jwt.MapClaims) (string,error){
		// Create your custom logic to assemble a outgoing token, wheatever it looks like
		return "myresultingToken",nil
	}})
```

#### Create JWTs 
 
For a convenient creation of JWTs, start the proxy as follows:
```go
	jwtCreator := jwtexchange.DefaultJwtCreator(func(claims jwt.MapClaims) jwt.Claims {
		claims["user_role"] = "admin"
		return claims
	})
	
	proxy.Start(jwtCreator)
```

This will set the following standard claims automatically based on the configuration

| Claim | Meaning                                     | Value                                                  | Environment variable     | Default  |     
|-------|---------------------------------------------| -------------------------------------------------------|--------------------------|----------------------|     
| `sub` |  The subject                                | The `sub` claim from the incoming token                |                          |                          |     
| `iat` |  Issued at                                  | Current unix timestamp (epoch)                         |                          |   |     
| `nbf` |  Not before (when the token becomes valid)  | Current unix timestamp (epoch)                         |                          |     |     
| `exp` |  Expired (when the token becomes invalid)   | Current unix timestamp (epoch) + TTL from env variable | `OUTGOING_TOKEN_TTL_SEC` | now + 3                      |     
| `aud` |  The audience for the created token         | From config                                            | `OUTGOING_AUDIENCE`      |      |     
