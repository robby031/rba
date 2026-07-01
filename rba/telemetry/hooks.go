// Package telemetry menyediakan antarmuka untuk observability.
//
// Implementasi dapat menggunakan OpenTelemetry Go atau logger apa pun
// yang sesuai. Package ini tidak mewajibkan dependency telemetry tertentu;
// pengguna cukup mengimplementasikan antarmuka yang disediakan.
package telemetry

import (
	"context"
	"time"

	"github.com/robby031/rba/rba"
)

// EventHook dipanggil oleh Assessor untuk setiap peristiwa penting
// dalam siklus evaluasi RBA.
type EventHook interface {
	// OnAssessment dipanggil setelah evaluasi selesai.
	OnAssessment(ctx context.Context, in rba.AssessmentInput, a rba.Assessment, d rba.Decision, latency time.Duration, err error)
}

// EventHookFunc adalah adapter fungsional untuk EventHook.
type EventHookFunc func(ctx context.Context, in rba.AssessmentInput, a rba.Assessment, d rba.Decision, latency time.Duration, err error)

func (f EventHookFunc) OnAssessment(ctx context.Context, in rba.AssessmentInput, a rba.Assessment, d rba.Decision, latency time.Duration, err error) {
	f(ctx, in, a, d, latency, err)
}

// MetricsCollector mengumpulkan metrik untuk pemantauan.
type MetricsCollector interface {
	// IncAssessment mencatat volume evaluasi.
	IncAssessment(ctx context.Context, level rba.RiskLevel, action rba.DecisionAction)

	// ObserveLatency mencatat latensi evaluasi dalam milidetik.
	ObserveLatency(ctx context.Context, latencyMs float64)

	// IncMissingSignal mencatat collector yang tidak mengembalikan signal.
	IncMissingSignal(ctx context.Context, collectorName string)
}

// Logger adalah antarmuka logging minimal.
type Logger interface {
	Info(ctx context.Context, msg string, keysAndValues ...any)
	Warn(ctx context.Context, msg string, keysAndValues ...any)
	Error(ctx context.Context, msg string, keysAndValues ...any)
}

// NoopMetricsCollector adalah implementasi MetricsCollector yang tidak melakukan apa-apa.
// Berguna sebagai default agar tidak perlu nil check.
type NoopMetricsCollector struct{}

func (NoopMetricsCollector) IncAssessment(_ context.Context, _ rba.RiskLevel, _ rba.DecisionAction) {}
func (NoopMetricsCollector) ObserveLatency(_ context.Context, _ float64)                            {}
func (NoopMetricsCollector) IncMissingSignal(_ context.Context, _ string)                           {}
