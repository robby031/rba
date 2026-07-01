// Package feature menyediakan implementasi FeatureBuilder default.
//
// FeatureBuilder mengubah signal mentah menjadi feature yang stabil dan
// terverifikasi, siap digunakan sebagai input RiskEngine.
package feature

import (
	"context"
	"strings"
	"time"

	"github.com/robby031/rba/rba"
)

// DefaultBuilder adalah implementasi FeatureBuilder yang menghasilkan
// feature umum untuk RBA.
//
// Feature yang dihasilkan:
//   - "is_new_device": true jika device ID tidak dikenal
//   - "is_new_country": true jika negara tidak dikenal
//   - "is_new_asn": true jika ASN tidak dikenal
//   - "hour_of_day": jam (0-23) saat request terjadi
//   - "is_weekend": true jika request terjadi di akhir pekan
//   - "is_private_ip": true jika IP termasuk private range
type DefaultBuilder struct{}

func NewDefaultBuilder() *DefaultBuilder {
	return &DefaultBuilder{}
}

func (b *DefaultBuilder) Build(_ context.Context, in rba.AssessmentInput, signals []rba.Signal) ([]rba.Feature, error) {
	var features []rba.Feature

	// Waktu
	hour := in.OccurredAt.Hour()
	features = append(features, rba.Feature{Name: "hour_of_day", Value: hour})

	weekday := in.OccurredAt.Weekday()
	isWeekend := weekday == time.Saturday || weekday == time.Sunday
	features = append(features, rba.Feature{Name: "is_weekend", Value: isWeekend})

	// Parse sinyal
	signalMap := make(map[string]any)
	for _, s := range signals {
		signalMap[s.Name] = s.Value
	}

	// IP
	if isPrivate, ok := signalMap["ip.is_private"]; ok {
		features = append(features, rba.Feature{Name: "is_private_ip", Value: isPrivate})
	}

	return features, nil
}

// HistoryAwareBuilder adalah DefaultBuilder yang juga menggunakan data histori
// untuk menghasilkan feature seperti "is_new_device", "is_new_country", dll.
type HistoryAwareBuilder struct {
	historyProvider HistoryProvider
}

// HistoryProvider menyediakan data histori subjek untuk pembangunan feature.
type HistoryProvider interface {
	GetKnownCountries(ctx context.Context, subjectID string) ([]string, error)
	GetKnownASN(ctx context.Context, subjectID string) ([]string, error)
	GetKnownDeviceIDs(ctx context.Context, subjectID string) ([]string, error)
}

func NewHistoryAwareBuilder(provider HistoryProvider) *HistoryAwareBuilder {
	return &HistoryAwareBuilder{historyProvider: provider}
}

func (b *HistoryAwareBuilder) Build(ctx context.Context, in rba.AssessmentInput, signals []rba.Signal) ([]rba.Feature, error) {
	// Gunakan DefaultBuilder untuk feature dasar
	defaultBuilder := NewDefaultBuilder()
	features, err := defaultBuilder.Build(ctx, in, signals)
	if err != nil {
		return nil, err
	}

	if b.historyProvider == nil || in.SubjectID == "" {
		return features, nil
	}

	// Parse signal
	signalMap := make(map[string]any)
	for _, s := range signals {
		signalMap[s.Name] = s.Value
	}

	// Device
	if deviceID, ok := signalMap["device.id"]; ok {
		knownIDs, err := b.historyProvider.GetKnownDeviceIDs(ctx, in.SubjectID)
		if err != nil {
			return nil, err
		}
		isNew := !contains(knownIDs, deviceID)
		features = append(features, rba.Feature{Name: "is_new_device", Value: isNew})
	}

	// Country
	if country, ok := signalMap["geo.country"]; ok {
		knownCountries, err := b.historyProvider.GetKnownCountries(ctx, in.SubjectID)
		if err != nil {
			return nil, err
		}
		isNew := !contains(knownCountries, country)
		features = append(features, rba.Feature{Name: "is_new_country", Value: isNew})
	}

	// ASN
	if asn, ok := signalMap["geo.asn"]; ok {
		knownASN, err := b.historyProvider.GetKnownASN(ctx, in.SubjectID)
		if err != nil {
			return nil, err
		}
		isNew := !contains(knownASN, asn)
		features = append(features, rba.Feature{Name: "is_new_asn", Value: isNew})
	}

	return features, nil
}

func contains(slice []string, item any) bool {
	itemStr, ok := item.(string)
	if !ok {
		return false
	}
	for _, s := range slice {
		if strings.EqualFold(s, itemStr) {
			return true
		}
	}
	return false
}
