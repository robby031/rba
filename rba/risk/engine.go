// Package risk menyediakan implementasi RiskEngine untuk menghitung
// risk score dan risk level berdasarkan feature yang sudah dibangun.
//
// RiskEngine bertanggung jawab untuk transformasi feature menjadi
// score numerik dan level diskret, lengkap dengan alasan (reasons).
package risk

import (
	"context"

	"github.com/robby031/rba/rba"
)

// RuleBasedEngine adalah implementasi RiskEngine berbasis aturan sederhana.
//
// Setiap feature dapat memberikan kontribusi positif (menambah risiko)
// terhadap score akhir. Risk level ditentukan berdasarkan threshold.
type RuleBasedEngine struct {
	// FeatureWeights menentukan kontribusi setiap feature ke risk score.
	// Key adalah nama feature, value adalah poin yang ditambahkan jika
	// feature bernilai true (untuk boolean) atau match (untuk value).
	FeatureWeights map[string]float64

	// Thresholds menentukan batas score untuk setiap risk level.
	Thresholds RiskThresholds
}

// RiskThresholds menentukan batas score untuk setiap risk level.
type RiskThresholds struct {
	Medium float64 // Score >= Medium masuk RiskMedium
	High   float64 // Score >= High masuk RiskHigh
}

// DefaultThresholds adalah threshold yang direkomendasikan untuk MVP.
// Dapat disesuaikan dengan data produksi masing-masing.
var DefaultThresholds = RiskThresholds{
	Medium: 30,
	High:   70,
}

// DefaultFeatureWeights adalah bobot default untuk feature umum RBA.
var DefaultFeatureWeights = map[string]float64{
	"is_new_device":  40,
	"is_new_country": 30,
	"is_new_asn":     20,
	"is_private_ip":  10,
	"is_weekend":     5,
	"ua.is_empty":    25,
}

func NewRuleBasedEngine() *RuleBasedEngine {
	return &RuleBasedEngine{
		FeatureWeights: DefaultFeatureWeights,
		Thresholds:     DefaultThresholds,
	}
}

func NewRuleBasedEngineWithWeights(weights map[string]float64, thresholds RiskThresholds) *RuleBasedEngine {
	e := NewRuleBasedEngine()
	if weights != nil {
		e.FeatureWeights = weights
	}
	e.Thresholds = thresholds
	return e
}

func (e *RuleBasedEngine) Assess(_ context.Context, _ rba.AssessmentInput, features []rba.Feature) (rba.Assessment, error) {
	var score float64
	var reasons []rba.Reason

	for _, f := range features {
		weight, ok := e.FeatureWeights[f.Name]
		if !ok {
			continue
		}

		// Hitung kontribusi berdasarkan tipe nilai
		contributes := false
		switch v := f.Value.(type) {
		case bool:
			contributes = v
		case string:
			contributes = v != ""
		case int:
			contributes = v > 0
		case float64:
			contributes = v > 0
		default:
			contributes = f.Value != nil
		}

		if contributes {
			score += weight
			reasons = append(reasons, rba.Reason{
				Code:     "feature_" + f.Name,
				Message:  "feature '" + f.Name + "' contributed to risk",
				Severity: "info",
			})
		}
	}

	// Normalisasi score ke 0-100
	if score > 100 {
		score = 100
	}

	level := rba.RiskLow
	if score >= e.Thresholds.Medium {
		level = rba.RiskMedium
	}
	if score >= e.Thresholds.High {
		level = rba.RiskHigh
	}

	return rba.Assessment{
		Score:   score,
		Level:   level,
		Reasons: reasons,
	}, nil
}
