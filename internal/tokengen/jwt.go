package tokengen

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"time"
)

type jwtClaims struct {
	jwt.StandardClaims
	Email string
}

type JWTGenerator struct {
	secretKey string
	issuer    string
	ttl       time.Duration
}

func (g *JWTGenerator) Generate(userEmail string) (string, error) {
	claims := &jwtClaims{
		Email: userEmail,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(g.ttl).Unix(),
			Issuer:    g.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, signErr := token.SignedString([]byte(g.secretKey))

	if signErr != nil {
		return "", fmt.Errorf("can't sign token:%w", signErr)
	}

	return signedToken, nil
}

func (g *JWTGenerator) ValidateTokenAndGetEmail(signedToken string) (string, error) {
	token, parseTokenErr := jwt.ParseWithClaims(
		signedToken,
		&jwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(g.secretKey), nil
		},
	)

	var ve *jwt.ValidationError
	if errors.As(parseTokenErr, &ve) {
		if ve.Errors&jwt.ValidationErrorExpired != 0 {
			return "", errors.New("token has expired")
		}
	}

	if parseTokenErr != nil {
		log.Println(parseTokenErr)
		return "", errors.New("can't parse token")
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok {
		return "", errors.New("invalid claims passed")
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		return "", errors.New("token has expired")
	}

	if claims.Issuer != g.issuer {
		return "", errors.New("invalid issuer")
	}

	return claims.Email, nil
}

func NewJWTGenerator(secretKey, issuer string, ttl time.Duration) *JWTGenerator {
	return &JWTGenerator{
		secretKey: secretKey,
		issuer:    issuer,
		ttl:       ttl,
	}
}
