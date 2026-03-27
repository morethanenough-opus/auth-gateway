package authgateway

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// GenerateSecret generates a secret key of a specified length.
func GenerateSecret(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err!= nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateToken generates a JWT token with the given claims and secret.
func GenerateToken(claims map[string]interface{}, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken validates a JWT token with the given secret and returns the claims.
func ValidateToken(tokenString string, secret string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC);!ok {
			return nil, errors.New("invalid token method")
		}
		return []byte(secret), nil
	})
	if err!= nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// GetBearerToken extracts the Bearer token from the Authorization header.
func GetBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if!strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("invalid Authorization header")
	}
	return authHeader[7:], nil
}

// GetRemoteIP returns the remote IP address from the request.
func GetRemoteIP(r *http.Request) string {
	if r.RemoteAddr!= "" {
		return r.RemoteAddr
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip!= "" {
		return ip
	}
	return r.Header.Get("X-Real-IP")
}

// GetUserAgent returns the User-Agent header from the request.
func GetUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

// GetContentType returns the Content-Type header from the request.
func GetContentType(r *http.Request) string {
	return r.Header.Get("Content-Type")
}

// GetRequestBody returns the request body as a string.
func GetRequestBody(r *http.Request) (string, error) {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, r.Body); err!= nil {
		return "", err
	}
	return buf.String(), nil
}

// GetEnvironmentVariable returns the value of the environment variable with the given name.
func GetEnvironmentVariable(name string) string {
	return os.Getenv(name)
}

// GetCurrentTime returns the current time in the given format.
func GetCurrentTime(layout string) string {
	return time.Now().Format(layout)
}

// IsDebug returns true if the application is running in debug mode.
func IsDebug() bool {
	return os.Getenv("DEBUG") == "true"
}

// LogError logs an error with the given message and stack trace.
func LogError(message string, err error) {
	log.Printf("Error: %s - %s\n", message, err.Error())
}

// LogWarning logs a warning with the given message.
func LogWarning(message string) {
	log.Println("Warning: " + message)
}

// LogInfo logs an info message with the given message.
func LogInfo(message string) {
	log.Println("Info: " + message)
}

// LogDebug logs a debug message with the given message.
func LogDebug(message string) {
	if IsDebug() {
		log.Println("Debug: " + message)
	}
}