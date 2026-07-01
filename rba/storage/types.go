// Package storage menyediakan antarmuka adapter untuk persistence.
//
// Antarmuka di sini adalah contract yang harus diimplementasikan oleh
// adapter storage konkret (SQL, Redis, mock, dll). Package ini tidak
// menyertakan implementasi bawaan; pengguna library diharapkan menyediakan
// implementasi sesuai infrastruktur yang digunakan.
package storage

import (
	"context"
	"time"

	"github.com/robby031/rba/rba"
)

// EventStore menyimpan dan mengambil riwayat peristiwa autentikasi.
type EventStore interface {
	AppendAuthEvent(ctx context.Context, e AuthEvent) error
	ListRecentAuthEvents(ctx context.Context, subjectID string, since time.Time, limit int) ([]AuthEvent, error)
}

// SessionStore menyimpan dan mengambil state sesi.
type SessionStore interface {
	GetSession(ctx context.Context, sessionID string) (*rba.SessionState, error)
	SaveSession(ctx context.Context, s *rba.SessionState) error
	InvalidateSession(ctx context.Context, sessionID string) error
}

// ProfileStore menyimpan dan mengambil profil subjek (pengguna/perangkat).
type ProfileStore interface {
	GetSubjectProfile(ctx context.Context, tenantID, subjectID string) (*SubjectProfile, error)
	UpsertSubjectProfile(ctx context.Context, p *SubjectProfile) error
}

// PolicyStore menyimpan dan mengambil kebijakan (policy bundle).
type PolicyStore interface {
	GetPolicyBundle(ctx context.Context, tenantID string) (*rba.PolicyBundle, error)
}

// AuthEvent adalah riwayat satu peristiwa autentikasi yang dicatat.
type AuthEvent struct {
	EventID      string
	TenantID     string
	SubjectID    string
	SessionID    string
	Action       string
	OccurredAt   time.Time
	IPAddress    string
	UserAgent    string
	GeoCountry   string
	ASN          string
	DeviceIDHash string
	RiskScore    float64
	RiskLevel    string
	Decision     string
	Reasons      []string
}

// SubjectProfile adalah ringkasan profil subjek (pengguna) yang digunakan
// sebagai baseline untuk deteksi anomali.
type SubjectProfile struct {
	TenantID   string
	SubjectID  string
	LastSeenAt time.Time

	// KnownCountries adalah daftar kode negara yang pernah dipakai subjek.
	KnownCountries []string

	// KnownASN adalah daftar ASN yang pernah dipakai subjek.
	KnownASN []string

	// KnownDeviceIDHashes adalah daftar device ID hash yang pernah dipakai.
	KnownDeviceIDHashes []string

	// PreferredChallenge adalah metode challenge pilihan subjek, misal "totp".
	PreferredChallenge string

	// MinRequiredAcrByRisk memetakan risk level ke acr minimum yang diperlukan.
	// Contoh: {"medium": "phr", "high": "phrh"}
	MinRequiredAcrByRisk map[string]string
}
