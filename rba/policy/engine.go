package policy

import (
	"context"
	"fmt"
	"sort"

	"github.com/robby031/rba/rba"
)

// RuleBasedEngine adalah implementasi PolicyEngine yang mengevaluasi
// assessment terhadap serangkaian aturan (PolicyRule).
//
// Aturan dievaluasi berdasarkan prioritas (ascending). Aturan dengan
// prioritas lebih kecil dievaluasi lebih dulu. Rule pertama yang cocok
// akan menentukan keputusan.
type RuleBasedEngine struct {
	bundle *rba.PolicyBundle
}

// NewRuleBasedEngine membuat engine dengan bundle yang diberikan.
// Bundle bisa diubah setelah inisialisasi via SetPolicyBundle.
func NewRuleBasedEngine(bundle *rba.PolicyBundle) *RuleBasedEngine {
	return &RuleBasedEngine{bundle: bundle}
}

// SetPolicyBundle mengganti policy bundle yang aktif.
func (e *RuleBasedEngine) SetPolicyBundle(bundle *rba.PolicyBundle) {
	e.bundle = bundle
}

func (e *RuleBasedEngine) Decide(_ context.Context, _ rba.AssessmentInput, a rba.Assessment) (rba.Decision, error) {
	if e.bundle == nil || len(e.bundle.Rules) == 0 {
		return e.defaultDecision(a), nil
	}

	// Urutkan berdasarkan prioritas (ascending)
	sorted := make([]rba.PolicyRule, len(e.bundle.Rules))
	copy(sorted, e.bundle.Rules)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].Name < sorted[j].Name
	})

	for _, rule := range sorted {
		if matchRule(rule, a) {
			action := rba.DecisionAction(rule.ThenAction)
			dec := rba.Decision{
				Action:        action,
				RotateSession: action == rba.DecisionAllow || action == rba.DecisionChallenge,
				Tags: map[string]string{
					"policy.name":    rule.Name,
					"policy.version": e.bundle.Version,
				},
			}
			if action == rba.DecisionChallenge {
				dec.Challenge = &rba.Challenge{
					Type:   rule.Challenge,
					MinAcr: rule.MinAcr,
				}
			}
			if action == rba.DecisionDeny {
				dec.DenyReason = fmt.Sprintf("blocked by policy rule: %s", rule.Name)
			}
			return dec, nil
		}
	}

	return e.defaultDecision(a), nil
}

// defaultDecision mengembalikan keputusan default berdasarkan risk level.
func (e *RuleBasedEngine) defaultDecision(a rba.Assessment) rba.Decision {
	switch a.Level {
	case rba.RiskLow:
		return rba.Decision{
			Action:        rba.DecisionAllow,
			RotateSession: false,
			Tags:          map[string]string{"policy": "default", "reason": "low_risk"},
		}
	case rba.RiskMedium:
		return rba.Decision{
			Action:        rba.DecisionChallenge,
			ReauthNeeded:  true,
			RotateSession: true,
			Challenge: &rba.Challenge{
				Type:   "totp",
				MinAcr: "phr",
			},
			Tags: map[string]string{"policy": "default", "reason": "medium_risk"},
		}
	case rba.RiskHigh:
		return rba.Decision{
			Action:     rba.DecisionDeny,
			DenyReason: "high risk assessment",
			Tags:       map[string]string{"policy": "default", "reason": "high_risk"},
		}
	default:
		return rba.Decision{
			Action:     rba.DecisionDeny,
			DenyReason: fmt.Sprintf("unrecognized risk level: %s", a.Level),
			Tags:       map[string]string{"policy": "default", "reason": "unknown_risk"},
		}
	}
}

// matchRule memeriksa apakah assessment memenuhi kondisi sebuah rule.
//
// Saat ini mendukung pencocokan sederhana:
//   - "risk_level": mencocokkan string level
//   - "score_min": score >= threshold
//   - "score_max": score <= threshold
func matchRule(rule rba.PolicyRule, a rba.Assessment) bool {
	if len(rule.When) == 0 {
		return false
	}

	for key, expected := range rule.When {
		switch key {
		case "risk_level":
			if actual := string(a.Level); actual != expected {
				return false
			}
		case "score_min":
			threshold, ok := toFloat64(expected)
			if !ok || a.Score < threshold {
				return false
			}
		case "score_max":
			threshold, ok := toFloat64(expected)
			if !ok || a.Score > threshold {
				return false
			}
		default:
			// Abaikan key yang tidak dikenal (forward compatibility)
			continue
		}
	}

	return true
}

func toFloat64(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case uint64:
		return float64(val), true
	case float32:
		return float64(val), true
	default:
		return 0, false
	}
}
