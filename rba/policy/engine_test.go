package policy

import (
	"context"
	"testing"

	"github.com/robby031/rba/rba"
)

func TestRuleBasedEngine_NoBundle(t *testing.T) {
	e := NewRuleBasedEngine(nil)

	tests := []struct {
		name  string
		level rba.RiskLevel
		want  rba.DecisionAction
	}{
		{"low risk should allow", rba.RiskLow, rba.DecisionAllow},
		{"medium risk should challenge", rba.RiskMedium, rba.DecisionChallenge},
		{"high risk should deny", rba.RiskHigh, rba.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := rba.Assessment{Score: 50, Level: tt.level}
			dec, err := e.Decide(context.Background(), rba.AssessmentInput{}, a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Action != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, dec.Action)
			}
		})
	}
}

func TestRuleBasedEngine_WithBundle(t *testing.T) {
	bundle := &rba.PolicyBundle{
		Version: "v1",
		Rules: []rba.PolicyRule{
			{
				Name:       "block-high-risk",
				Priority:   10,
				When:       map[string]any{"risk_level": "high"},
				ThenAction: "deny",
			},
			{
				Name:       "challenge-medium-risk",
				Priority:   20,
				When:       map[string]any{"risk_level": "medium"},
				ThenAction: "challenge",
				Challenge:  "webauthn",
				MinAcr:     "phrh",
			},
			{
				Name:       "custom-high-score",
				Priority:   5,
				When:       map[string]any{"score_min": 90.0},
				ThenAction: "deny",
			},
		},
	}

	e := NewRuleBasedEngine(bundle)

	tests := []struct {
		name  string
		level rba.RiskLevel
		score float64
		want  rba.DecisionAction
	}{
		{"high risk", rba.RiskHigh, 80, rba.DecisionDeny},
		{"medium risk", rba.RiskMedium, 50, rba.DecisionChallenge},
		{"low risk", rba.RiskLow, 10, rba.DecisionAllow},
		{"high score", rba.RiskLow, 95, rba.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := rba.Assessment{Score: tt.score, Level: tt.level}
			dec, err := e.Decide(context.Background(), rba.AssessmentInput{}, a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Action != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, dec.Action)
			}
		})
	}
}

func TestRuleBasedEngine_PriorityOrder(t *testing.T) {
	bundle := &rba.PolicyBundle{
		Version: "v1",
		Rules: []rba.PolicyRule{
			{
				Name:       "low-priority-first",
				Priority:   100,
				When:       map[string]any{"risk_level": "high"},
				ThenAction: "allow",
			},
			{
				Name:       "high-priority",
				Priority:   1,
				When:       map[string]any{"risk_level": "high"},
				ThenAction: "deny",
			},
		},
	}

	e := NewRuleBasedEngine(bundle)
	a := rba.Assessment{Score: 100, Level: rba.RiskHigh}
	dec, err := e.Decide(context.Background(), rba.AssessmentInput{}, a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != rba.DecisionDeny {
		t.Fatalf("expected deny (high priority), got %s", dec.Action)
	}
	if dec.Tags["policy.name"] != "high-priority" {
		t.Fatalf("expected policy.name=high-priority, got %s", dec.Tags["policy.name"])
	}
}

func TestRuleBasedEngine_SetBundle(t *testing.T) {
	e := NewRuleBasedEngine(nil)
	a := rba.Assessment{Score: 0, Level: rba.RiskLow}

	// Tanpa bundle → allow
	dec, _ := e.Decide(context.Background(), rba.AssessmentInput{}, a)
	if dec.Action != rba.DecisionAllow {
		t.Fatalf("expected allow without bundle, got %s", dec.Action)
	}

	// Set bundle → deny high risk
	e.SetPolicyBundle(&rba.PolicyBundle{
		Version: "v2",
		Rules: []rba.PolicyRule{
			{
				Name:       "deny-high",
				Priority:   1,
				When:       map[string]any{"risk_level": "high"},
				ThenAction: "deny",
			},
		},
	})

	a.Level = rba.RiskHigh
	dec, _ = e.Decide(context.Background(), rba.AssessmentInput{}, a)
	if dec.Action != rba.DecisionDeny {
		t.Fatalf("expected deny after SetPolicyBundle, got %s", dec.Action)
	}
}
