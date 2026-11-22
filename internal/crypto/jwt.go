package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrJWTMalformed    = errors.New("jwt malformed")
	ErrJWTBadSignature = errors.New("jwt bad signature")
	ErrJWTExpired      = errors.New("jwt expired")
)

type JWTClaims struct {
	AccountID string `json:"sub"`
	DeviceID  string `json:"did"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func b64encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// SignJWT serialises and signs the claims with the given Ed25519 private key.
// json.Marshal is infallible for jwtHeader and JWTClaims (no maps, no chans, no
// floats outside JSON range), so no error return is necessary.
func SignJWT(priv ed25519.PrivateKey, claims JWTClaims) string {
	headerJSON, _ := json.Marshal(jwtHeader{Alg: "EdDSA", Typ: "JWT"})
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}
	payloadJSON, _ := json.Marshal(claims)

	signingInput := b64encode(headerJSON) + "." + b64encode(payloadJSON)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + b64encode(sig)
}

func VerifyJWT(pub ed25519.PublicKey, token string, now time.Time) (JWTClaims, error) {
	var claims JWTClaims

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, ErrJWTMalformed
	}

	headerBytes, err := b64decode(parts[0])
	if err != nil {
		return claims, ErrJWTMalformed
	}
	var h jwtHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return claims, ErrJWTMalformed
	}
	if h.Alg != "EdDSA" || h.Typ != "JWT" {
		return claims, ErrJWTMalformed
	}

	payloadBytes, err := b64decode(parts[1])
	if err != nil {
		return claims, ErrJWTMalformed
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return claims, ErrJWTMalformed
	}

	sig, err := b64decode(parts[2])
	if err != nil {
		return claims, ErrJWTMalformed
	}

	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return claims, ErrJWTBadSignature
	}

	if claims.ExpiresAt > 0 && now.Unix() >= claims.ExpiresAt {
		return claims, ErrJWTExpired
	}

	return claims, nil
}
