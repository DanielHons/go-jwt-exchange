package jwt_exchange

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
)

func TestJwtCreation(t *testing.T) {
	creator := JwtCreator_HS256{
		ClaimsMapper: func(claims jwt.MapClaims) jwt.Claims {
			return claims
		},
		JwtSecret: []byte("VerySecureSecret"),
	}

	claims := jwt.MapClaims{}
	claims["sub"] = "TestUser"
	claims["exp"] = 64 // should not be ovewritten since the claimsMapper is default

	token, err := creator.createToken(claims)

	if err != nil {
		t.Error("Could not create token: ", err)
	}

	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjY0LCJzdWIiOiJUZXN0VXNlciJ9.kZn4F_39ZkrdDTbPxL7gmumSjCD-nykC5VF2XnJOCLE"
	if token != expectedToken {
		t.Error("Token " + token + " does not match " + expectedToken)
	}

}

func TestJwtCreationWithCustomMapper(t *testing.T) {
	creator := JwtCreator_HS256{
		ClaimsMapper: func(claims jwt.MapClaims) jwt.Claims {
			claims["exp"] = 4711 //changed
			return claims
		},
		JwtSecret: []byte("VerySecureSecret"),
	}

	claims := jwt.MapClaims{}
	claims["sub"] = "TestUser"
	claims["exp"] = 64 // should be ovewritten by the mapper

	token, err := creator.createToken(claims)

	if err != nil {
		t.Error("Could not create token: ", err)
	}

	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ3MTEsInN1YiI6IlRlc3RVc2VyIn0.nGJxVyFwvnz1Vhr9tEGbJEX24DbfWzxv3UQfXBoyhjA"
	if token != expectedToken {
		t.Error("Token " + token + " does not match " + expectedToken)
	}

}

func TestFailsInThePipeline(t *testing.T) {
	t.Error("Expected error")
}
