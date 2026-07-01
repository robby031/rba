package rba

import (
	"context"
	"testing"
	"time"
)

func TestAssessor_NilComponents(t *testing.T) {
	a := NewAssessor(nil, nil, nil, nil)
	if a == nil {
		t.Fatal("NewAssessor should return non-nil with nil components")
	}

	in := AssessmentInput{
		SubjectID:  "test",
		OccurredAt: time.Now(),
		Action:     "login",
	}

	_, dec, err := a.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != DecisionAllow {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
}

func TestAssessor_WithCollectors(t *testing.T) {
	collector := &mockCollector{name: "test", signals: []Signal{
		{Name: "test.signal", Value: "value", Confidence: 1.0, Source: "test"},
	}}
	fb := &mockFeatureBuilder{}
	re := &mockRiskEngine{}
	pe := &mockPolicyEngine{}

	a := NewAssessor(
		[]SignalCollector{collector},
		fb,
		re,
		pe,
	)

	in := AssessmentInput{
		SubjectID:  "user-1",
		OccurredAt: time.Now(),
		Action:     "login",
		IPAddress:  "1.2.3.4",
	}

	assess, dec, err := a.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dec.Action != DecisionAllow {
		t.Fatalf("expected allow, got %s", dec.Action)
	}
	if assess.Score != 50 {
		t.Fatalf("expected score 50, got %.2f", assess.Score)
	}
	if len(assess.Signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(assess.Signals))
	}
	if assess.Signals[0].Name != "test.signal" {
		t.Fatalf("unexpected signal name: %s", assess.Signals[0].Name)
	}
}

type mockCollector struct {
	name    string
	signals []Signal
	err     error
}

func (m *mockCollector) Name() string { return m.name }
func (m *mockCollector) Collect(_ context.Context, _ AssessmentInput) ([]Signal, error) {
	return m.signals, m.err
}

type mockFeatureBuilder struct {
	features []Feature
	err      error
}

func (m *mockFeatureBuilder) Build(_ context.Context, _ AssessmentInput, _ []Signal) ([]Feature, error) {
	return m.features, m.err
}

type mockRiskEngine struct {
	assessment Assessment
	err        error
}

func (m *mockRiskEngine) Assess(_ context.Context, _ AssessmentInput, _ []Feature) (Assessment, error) {
	if m.err != nil {
		return Assessment{}, m.err
	}
	if m.assessment.Score == 0 && m.assessment.Level == "" {
		return Assessment{Score: 50, Level: RiskMedium}, nil
	}
	return m.assessment, m.err
}

type mockPolicyEngine struct {
	decision Decision
	err      error
}

func (m *mockPolicyEngine) Decide(_ context.Context, _ AssessmentInput, _ Assessment) (Decision, error) {
	if m.err != nil {
		return Decision{}, m.err
	}
	if m.decision.Action == "" {
		return Decision{Action: DecisionAllow}, nil
	}
	return m.decision, m.err
}
