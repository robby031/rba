// Package rba menyediakan tipe inti untuk Risk-Based Authentication.
//
// Package ini mendefinisikan model data dan antarmuka yang menjadi fondasi
// seluruh library. Semua sub-package (signals, policy, storage, oidc, telemetry)
// bergantung pada tipe yang didefinisikan di sini.
package rba

import "time"

// RiskLevel merepresentasikan tingkat risiko diskret.
// Level ini lebih stabil untuk policy publik dibandingkan risk score
// numerik yang dapat berubah karena kalibrasi internal.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// DecisionAction merepresentasikan keputusan yang dapat diambil oleh policy engine.
type DecisionAction string

const (
	DecisionAllow     DecisionAction = "allow"
	DecisionChallenge DecisionAction = "challenge"
	DecisionDeny      DecisionAction = "deny"
	DecisionRestrict  DecisionAction = "restrict"
)

// AssessmentInput adalah konteks lengkap dari request yang akan dinilai risikonya.
// Semua field bersifat eksplisit -- tidak ada map generik untuk data penting --
// agar API tetap teraudit dengan baik.
type AssessmentInput struct {
	SubjectID  string
	TenantID   string
	RequestID  string
	OccurredAt time.Time

	// Action adalah jenis aksi yang sedang dievaluasi, misalnya:
	// "login", "token_refresh", "api_access", "change_password", "add_device".
	Action string

	IPAddress string
	UserAgent string
	Headers   map[string]string

	// Claims membawa informasi dari token/sesi yang sudah ada, misalnya
	// acr, amr, auth_time, dan scope.
	Claims map[string]any

	// Session adalah state sesi saat ini, nil jika tidak ada sesi aktif.
	Session *SessionState

	// CustomContext untuk data tambahan yang spesifik aplikasi.
	CustomContext map[string]any
}

// Signal adalah fakta mentah tentang percobaan autentikasi atau request.
// Signal berasal dari collector internal maupun eksternal.
type Signal struct {
	Name       string
	Value      any
	Confidence float64 // 0.0 - 1.0
	Source     string
}

// Feature adalah hasil transformasi/normalisasi dari satu atau lebih signal.
// Feature bersifat stabil dan terverifikasi, cocok sebagai input risk engine.
type Feature struct {
	Name  string
	Value any
}

// Reason adalah alasan explainable untuk sebuah assessment atau decision.
type Reason struct {
	Code     string
	Message  string
	Severity string // "info", "warning", "critical"
}

// Assessment adalah hasil komputasi risk engine.
// Berisi score numerik, level diskret, serta signal dan feature
// yang digunakan beserta alasan-alasannya.
type Assessment struct {
	Score    float64
	Level    RiskLevel
	Signals  []Signal
	Features []Feature
	Reasons  []Reason
}

// Challenge merepresentasikan mekanisme step-up yang diminta.
type Challenge struct {
	Type     string // "webauthn", "totp", "push", "sms"
	MinAcr   string
	MaxAge   *time.Duration
	Metadata map[string]any
}

// Decision adalah keputusan policy engine setelah mengevaluasi assessment.
type Decision struct {
	Action        DecisionAction
	Challenge     *Challenge
	ReauthNeeded  bool
	RotateSession bool
	DenyReason    string
	Tags          map[string]string
}

// SessionState menyimpan state sesi yang relevan untuk evaluasi risiko.
type SessionState struct {
	SessionID       string
	AuthenticatedAt time.Time
	CurrentAcr      string
	CurrentAmr      []string
	RiskLocked      bool
}

// PolicyBundle adalah kumpulan aturan kebijakan yang diversion.
type PolicyBundle struct {
	Version string
	Rules   []PolicyRule
}

// PolicyRule adalah satu aturan dalam policy bundle.
//
// When adalah map yang berisi kondisi yang harus dipenuhi. Key adalah
// nama field assessment atau input (misal "risk_level", "action"), value adalah
// nilai yang diharapkan untuk pencocokan.
type PolicyRule struct {
	Name       string
	Priority   int // Semakin kecil angka, semakin tinggi prioritas
	When       map[string]any
	ThenAction string // "allow", "challenge", "deny", "restrict"
	Challenge  string // jenis challenge jika ThenAction = "challenge"
	MinAcr     string
}
