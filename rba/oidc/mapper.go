// Package oidc menyediakan mapper untuk memproyeksikan hasil RBA ke
// klaim OIDC/OAuth (acr, amr, auth_time) serta helper untuk challenge
// step-up sesuai RFC 9470.
package oidc

import (
	"fmt"
	"time"

	"github.com/robby031/rba/rba"
)

// AssuranceLevel memetakan risk level internal ke acr value OIDC.
// Ini adalah default mapping yang dapat di-override oleh pengguna library.
type AssuranceLevel string

const (
	// AssuranceLow adalah acr untuk sesi dengan metode autentikasi dasar.
	AssuranceLow AssuranceLevel = "low"

	// AssuranceMedium adalah acr untuk sesi yang sudah melalui MFA ringan (TOTP).
	AssuranceMedium AssuranceLevel = "phr"

	// AssuranceHigh adalah acr untuk sesi dengan MFA phishing-resistant (WebAuthn).
	AssuranceHigh AssuranceLevel = "phrh"
)

// DefaultAssuranceMapping memetakan risk level ke acr yang diperlukan.
// Makin tinggi risiko, makin tinggi assurance yang diminta.
var DefaultAssuranceMapping = map[rba.RiskLevel]string{
	rba.RiskLow:    string(AssuranceLow),
	rba.RiskMedium: string(AssuranceMedium),
	rba.RiskHigh:   string(AssuranceHigh),
}

// Claims adalah representasi OIDC claims yang relevan untuk RBA.
type Claims struct {
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"` // Unix timestamp
}

// BuildClaims membangun OIDC claims dari session state.
//
// authTime adalah waktu autentikasi terakhir; jika nil, digunakan time.Now().
func BuildClaims(sess *rba.SessionState, authTime *time.Time) Claims {
	c := Claims{}

	if sess != nil {
		c.ACR = sess.CurrentAcr
		c.AMR = sess.CurrentAmr
	}

	if authTime != nil {
		c.AuthTime = authTime.Unix()
	} else if sess != nil {
		c.AuthTime = sess.AuthenticatedAt.Unix()
	} else {
		c.AuthTime = time.Now().Unix()
	}

	return c
}

// RequiredACR mengembalikan acr yang diperlukan untuk risk level tertentu.
// Menggunakan DefaultAssuranceMapping jika level tidak ditemukan.
func RequiredACR(level rba.RiskLevel) string {
	if acr, ok := DefaultAssuranceMapping[level]; ok {
		return acr
	}
	return string(AssuranceLow)
}

// StepUpChallengeHeader membangun value header WWW-Authenticate
// sesuai RFC 9470 untuk menandakan step-up diperlukan.
//
// Contoh output:
//
//	Bearer error="insufficient_user_authentication", acr_values="phr phrh", max_age=300
func StepUpChallengeHeader(requiredACR string, maxAgeSeconds int) string {
	header := fmt.Sprintf(
		`Bearer error="insufficient_user_authentication", acr_values="%s"`,
		requiredACR,
	)
	if maxAgeSeconds > 0 {
		header += fmt.Sprintf(`, max_age=%d`, maxAgeSeconds)
	}
	return header
}
