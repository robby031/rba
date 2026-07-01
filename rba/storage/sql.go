package storage

// Catatan: File ini menyediakan konstanta dan helper untuk implementasi
// adapter SQL. Pengguna library perlu mengimplementasikan antarmuka
// EventStore, SessionStore, ProfileStore, dan PolicyStore sesuai
// dengan database yang digunakan (PostgreSQL, MySQL, SQLite, dll).
//
// Contoh skema SQL untuk PostgreSQL dapat ditemukan di direktori
// _examples/sql/ pada repository ini.

// DefaultTableNames adalah nama tabel default yang direkomendasikan.
const (
	TableAuthEvents     = "auth_events"
	TableSessions       = "sessions"
	TableSubjectProfile = "subject_profiles"
	TablePolicyBundles  = "policy_bundles"
)
