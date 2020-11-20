package main

import (
	jwtexchange "github.com/DanielHons/go-jwt-exchange/jwt_exchange"
	"github.com/dgrijalva/jwt-go"
)

func main() {
	proxy := jwtexchange.NewProxy()

	//proxy.Start(jwtexchange.GenericTokenCreator{CreationFunc: func(claims jwt.MapClaims) (string,error){
	//	// Create your custom logic to assemble a outgoing token, wheatever it looks like
	//	return "baloo",nil
	//}})

	jwtCreator := jwtexchange.DefaultJwtCreator(func(claims jwt.MapClaims) jwt.Claims {
		claims["user_role"] = "admin"
		return claims
	})

	proxy.Start(jwtCreator)

	//proxy.Start(jwtexchange.DefaultJwtCreator(func(claims jwt.MapClaims) jwt.Claims {
	//	unix := time.Now().Unix()
	//	return OutgoingClaims{
	//		StandardClaims: jwt.StandardClaims{
	//			Audience: os.Getenv("OUTGOING_AUDIENCE"),
	//			ExpiresAt: unix + proxy.Config.TokenTTL,
	//			IssuedAt: unix,
	//			NotBefore: unix,
	//			Subject: claims["sub"].(string),
	//		},
	//		UserRole: "admin",
	//	}
	//}))
}

type OutgoingClaims struct {
	jwt.StandardClaims
	UserRole string `json:"user_role"`
}
