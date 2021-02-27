package jwt_exchange

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
)

func TestJwtCreation(t *testing.T) {
	creator := JwtCreator_HS256{
		JwtSecret: []byte("VerySecureSecret"),
	}

	claims := jwt.MapClaims{}
	claims["sub"] = "TestUser"
	claims["exp"] = 64

	token, err := creator.CreateToken(claims)

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
		JwtSecret: []byte("VerySecureSecret"),
	}

	claims := jwt.MapClaims{}
	claims["sub"] = "TestUser"
	claims["exp"] = 4711 // should be ovewritten by the mapper

	token, err := creator.CreateToken(claims)

	if err != nil {
		t.Error("Could not create token: ", err)
	}

	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQ3MTEsInN1YiI6IlRlc3RVc2VyIn0.nGJxVyFwvnz1Vhr9tEGbJEX24DbfWzxv3UQfXBoyhjA"
	if token != expectedToken {
		t.Error("Token " + token + " does not match " + expectedToken)
	}

}
