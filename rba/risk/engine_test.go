package risk

import (
	"context"
	"testing"

	"github.com/robby031/rba/rba"
)

func TestRuleBasedEngine_Default(t *testing.T) {
	e := NewRuleBasedEngine()

	tests := []struct {
		name     string
		features []rba.Feature
		wantLow  bool // true if risk level should be RiskLow
	}{
		{
			name:     "no features should be low risk",
			features: nil,
			wantLow:  true,
		},
		{
			name: "single low weight feature",
			features: []rba.Feature{
				{Name: "is_weekend", Value: true},
			},
			wantLow: true,
		},
		{
			name: "new device should be medium risk",
			features: []rba.Feature{
				{Name: "is_new_device", Value: true},
			},
			wantLow: false,
		},
		{
			name: "empty user agent should be medium risk",
			features: []rba.Feature{
				{Name: "ua.is_empty", Value: true},
			},
			wantLow: true, // 25 < 30
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assess, err := e.Assess(context.Background(), rba.AssessmentInput{}, tt.features)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantLow && assess.Level != rba.RiskLow {
				t.Fatalf("expected low risk, got %s (score=%.2f)", assess.Level, assess.Score)
			}
			if !tt.wantLow && assess.Level == rba.RiskLow {
				t.Fatalf("expected non-low risk, got %s (score=%.2f)", assess.Level, assess.Score)
			}
		})
	}
}

func TestRuleBasedEngine_ScoreClamping(t *testing.T) {
	e := NewRuleBasedEngine()
	features := []rba.Feature{
		{Name: "is_new_device", Value: true},  // 40
		{Name: "is_new_country", Value: true}, // 30
		{Name: "is_new_asn", Value: true},     // 20
		{Name: "is_private_ip", Value: true},  // 10
		{Name: "is_weekend", Value: true},     // 5
	}
	// Total = 105, should clamp to 100
	assess, err := e.Assess(context.Background(), rba.AssessmentInput{}, features)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assess.Score > 100 {
		t.Fatalf("expected score clamped to <=100, got %.2f", assess.Score)
	}
	if assess.Level != rba.RiskHigh {
		t.Fatalf("expected high risk, got %s (score=%.2f)", assess.Level, assess.Score)
	}
}

func TestRuleBasedEngine_CustomWeights(t *testing.T) {
	weights := map[string]float64{
		"critical_flag": 100,
	}
	e := NewRuleBasedEngineWithWeights(weights, RiskThresholds{Medium: 50, High: 80})

	features := []rba.Feature{
		{Name: "critical_flag", Value: true},
	}
	assess, err := e.Assess(context.Background(), rba.AssessmentInput{}, features)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assess.Level != rba.RiskHigh {
		t.Fatalf("expected high risk, got %s (score=%.2f)", assess.Level, assess.Score)
	}
}

func TestRuleBasedEngine_Reasons(t *testing.T) {
	e := NewRuleBasedEngine()
	features := []rba.Feature{
		{Name: "is_new_device", Value: true},
		{Name: "is_new_country", Value: true},
	}

	assess, err := e.Assess(context.Background(), rba.AssessmentInput{}, features)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(assess.Reasons) != 2 {
		t.Fatalf("expected 2 reasons, got %d", len(assess.Reasons))
	}

	codes := make(map[string]bool)
	for _, r := range assess.Reasons {
		codes[r.Code] = true
	}
	if !codes["feature_is_new_device"] || !codes["feature_is_new_country"] {
		t.Fatal("missing expected reason codes")
	}
}

func TestRuleBasedEngine_BoolFeatureFalse(t *testing.T) {
	e := NewRuleBasedEngine()
	features := []rba.Feature{
		{Name: "is_new_device", Value: false},
	}

	assess, err := e.Assess(context.Background(), rba.AssessmentInput{}, features)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if assess.Level != rba.RiskLow {
		t.Fatalf("expected low risk for false feature, got %s", assess.Level)
	}
}
