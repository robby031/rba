package benchmark

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/robby031/rba/rba"
	"github.com/robby031/rba/rba/feature"
	"github.com/robby031/rba/rba/policy"
	"github.com/robby031/rba/rba/risk"
	"github.com/robby031/rba/rba/signals"
)

func benchInput() rba.AssessmentInput {
	return rba.AssessmentInput{
		SubjectID:  "user-bench-001",
		TenantID:   "tenant-a",
		RequestID:  "req-bench",
		OccurredAt: time.Now().UTC(),
		Action:     "login",
		IPAddress:  "203.0.113.42",
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		Headers: map[string]string{
			"X-Device-ID": "device-hash-bench",
		},
		Claims: map[string]any{
			"amr": []string{"pwd"},
		},
	}
}

func benchAssessor() *rba.Assessor {
	return rba.NewAssessor(
		[]rba.SignalCollector{
			signals.NewIPCollector(),
			signals.NewUserAgentCollector(),
			signals.NewDeviceCollector("X-Device-ID"),
		},
		feature.NewDefaultBuilder(),
		risk.NewRuleBasedEngine(),
		policy.NewRuleBasedEngine(nil),
	)
}

// Latency: Baseline

func BenchmarkAssessor_Baseline(b *testing.B) {
	a := rba.NewAssessor(nil, nil, nil, nil)
	ctx := context.Background()
	in := benchInput()

	for b.Loop() {
		a.Evaluate(ctx, in)
	}
}

// Latency: Full Pipeline

func BenchmarkAssessor_FullPipeline(b *testing.B) {
	a := benchAssessor()
	ctx := context.Background()
	in := benchInput()

	for b.Loop() {
		a.Evaluate(ctx, in)
	}
}

// Scalability: Many Collectors

func BenchmarkAssessor_ManyCollectors(b *testing.B) {
	for _, n := range []int{1, 5, 10, 25} {
		b.Run(fmt.Sprintf("collectors_%d", n), func(b *testing.B) {
			cc := make([]rba.SignalCollector, n)
			for i := range n {
				cc[i] = signals.NewIPCollector()
			}
			a := rba.NewAssessor(
				cc,
				feature.NewDefaultBuilder(),
				risk.NewRuleBasedEngine(),
				policy.NewRuleBasedEngine(nil),
			)
			ctx := context.Background()
			in := benchInput()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.Evaluate(ctx, in)
			}
		})
	}
}

// Scalability: Many Policy Rules

func BenchmarkAssessor_ManyRules(b *testing.B) {
	for _, n := range []int{1, 10, 50, 200, 1000} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			rules := make([]rba.PolicyRule, n)
			for i := range n {
				rules[i] = rba.PolicyRule{
					Name:       fmt.Sprintf("rule-%d", i),
					Priority:   i,
					When:       map[string]any{"risk_level": "critical"},
					ThenAction: "deny",
				}
			}
			rules[n-1] = rba.PolicyRule{
				Name:       "catch-all",
				Priority:   n,
				When:       map[string]any{"risk_level": "low"},
				ThenAction: "allow",
			}

			a := rba.NewAssessor(
				[]rba.SignalCollector{signals.NewIPCollector()},
				feature.NewDefaultBuilder(),
				risk.NewRuleBasedEngine(),
				policy.NewRuleBasedEngine(&rba.PolicyBundle{Version: "v1", Rules: rules}),
			)
			ctx := context.Background()
			in := benchInput()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.Evaluate(ctx, in)
			}
		})
	}
}

// Scalability: Many Features (Risk Engine Isolated)

func BenchmarkRiskEngine_ManyFeatures(b *testing.B) {
	for _, n := range []int{5, 20, 50, 100} {
		b.Run(fmt.Sprintf("features_%d", n), func(b *testing.B) {
			e := risk.NewRuleBasedEngine()
			features := make([]rba.Feature, n)
			for i := range n {
				features[i] = rba.Feature{
					Name:  fmt.Sprintf("feature_%d", i),
					Value: 1,
				}
			}
			for _, f := range features {
				e.FeatureWeights[f.Name] = 5
			}
			ctx := context.Background()
			in := benchInput()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Assess(ctx, in, features)
			}
		})
	}
}

// Scalability: Many Rules (Policy Engine Isolated)

func BenchmarkPolicyEngine_ManyRules(b *testing.B) {
	for _, n := range []int{1, 10, 50, 200, 1000} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			rules := make([]rba.PolicyRule, n)
			for i := range n {
				rules[i] = rba.PolicyRule{
					Name:       fmt.Sprintf("rule-%d", i),
					Priority:   i,
					When:       map[string]any{"risk_level": "critical"},
					ThenAction: "deny",
				}
			}
			rules[n-1] = rba.PolicyRule{
				Name:       "catch-all",
				Priority:   n,
				When:       map[string]any{"risk_level": "low"},
				ThenAction: "allow",
			}
			e := policy.NewRuleBasedEngine(&rba.PolicyBundle{Version: "v1", Rules: rules})
			ctx := context.Background()
			in := benchInput()
			assess := rba.Assessment{Score: 10, Level: rba.RiskLow}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Decide(ctx, in, assess)
			}
		})
	}
}

// Concurrency

func BenchmarkAssessor_Parallel(b *testing.B) {
	a := benchAssessor()
	inputs := make([]rba.AssessmentInput, 128)
	for i := range inputs {
		inputs[i] = rba.AssessmentInput{
			SubjectID:  fmt.Sprintf("user-%04d", i),
			TenantID:   "tenant-a",
			RequestID:  fmt.Sprintf("req-%04d", i),
			OccurredAt: time.Now().UTC(),
			Action:     "login",
			IPAddress:  fmt.Sprintf("203.0.113.%d", i%256),
			UserAgent:  "Mozilla/5.0",
			Headers:    map[string]string{"X-Device-ID": fmt.Sprintf("device-%04d", i)},
			Claims:     map[string]any{"amr": []string{"pwd"}},
		}
	}
	counter := int64(0)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			idx := int(counter) % len(inputs)
			counter++
			a.Evaluate(ctx, inputs[idx])
		}
	})
}

// Signal Collectors (Isolated)

func BenchmarkSignalCollectors(b *testing.B) {
	ctx := context.Background()
	in := benchInput()

	b.Run("IPCollector", func(b *testing.B) {
		c := signals.NewIPCollector()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Collect(ctx, in)
		}
	})

	b.Run("UserAgentCollector", func(b *testing.B) {
		c := signals.NewUserAgentCollector()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Collect(ctx, in)
		}
	})

	b.Run("DeviceCollector", func(b *testing.B) {
		c := signals.NewDeviceCollector("X-Device-ID")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Collect(ctx, in)
		}
	})
}
