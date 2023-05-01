package tokengen

import (
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/golang-jwt/jwt"
	"log"
	"time"
)

type jwtClaims struct {
	jwt.StandardClaims
	Email string
}

type JWTGenerator struct {
	secretAccessKey  string
	secretRefreshKey string
	issuer           string
	accessTTL        time.Duration
	refreshTTL       time.Duration
}

func (g *JWTGenerator) GenerateTokenPair(userEmail string) (entity.TokenPair, error) {
	accessToken, accessTokenErr := g.generateAccessToken(userEmail)
	if accessTokenErr != nil {
		return entity.TokenPair{}, accessTokenErr
	}

	refreshToken, refreshTokenErr := g.generateRefreshToken(userEmail)
	if refreshTokenErr != nil {
		return entity.TokenPair{}, accessTokenErr
	}

	return entity.TokenPair{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func (g *JWTGenerator) generateAccessToken(userEmail string) (string, error) {
	claims := &jwtClaims{
		Email: userEmail,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(g.accessTTL).Unix(),
			Issuer:    g.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, signErr := token.SignedString([]byte(g.secretAccessKey))
	if signErr != nil {
		return "", fmt.Errorf("can't sign access token:%w", signErr)
	}

	return signedToken, nil
}

func (g *JWTGenerator) generateRefreshToken(userEmail string) (string, error) {
	claims := &jwtClaims{
		Email: userEmail,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(g.refreshTTL).Unix(),
			Issuer:    g.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, signErr := token.SignedString([]byte(g.secretRefreshKey))
	if signErr != nil {
		return "", fmt.Errorf("can't sign refresh token:%w", signErr)
	}

	return signedToken, nil
}

func (g *JWTGenerator) ValidateAccessTokenAndGetEmail(signedToken string) (string, error) {
	token, parseTokenErr := jwt.ParseWithClaims(signedToken, &jwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(g.secretAccessKey), nil
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

	if claims.Issuer != g.issuer {
		return "", errors.New("invalid issuer")
	}

	return claims.Email, nil
}

func NewJWTGenerator(secretAccessKey, secretRefreshKey, issuer string,
	accessTTL, refreshTTL time.Duration) *JWTGenerator {
	return &JWTGenerator{
		secretAccessKey:  secretAccessKey,
		secretRefreshKey: secretRefreshKey,
		issuer:           issuer,
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
	}
}
