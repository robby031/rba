// Contoh penggunaan library RBA.
//
// Menunjukkan alur lengkap: setup collectors, feature builder,
// risk engine, policy engine, dan evaluasi.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/robby031/rba/rba"
	"github.com/robby031/rba/rba/feature"
	"github.com/robby031/rba/rba/policy"
	"github.com/robby031/rba/rba/risk"
	"github.com/robby031/rba/rba/signals"
)

func main() {
	ctx := context.Background()

	// 1. Setup collectors
	collectors := []rba.SignalCollector{
		signals.NewIPCollector(),
		signals.NewUserAgentCollector(),
		signals.NewDeviceCollector("X-Device-ID"),
	}

	// 2. Setup feature builder
	featureBuilder := feature.NewDefaultBuilder()

	// 3. Setup risk engine
	riskEngine := risk.NewRuleBasedEngineWithWeights(
		risk.DefaultFeatureWeights,
		risk.RiskThresholds{Medium: 30, High: 70},
	)

	// 4. Setup policy engine (tanpa bundle → default decision based on risk level)
	policyEngine := policy.NewRuleBasedEngine(nil)

	// 5. Buat assessor
	assessor := rba.NewAssessor(collectors, featureBuilder, riskEngine, policyEngine)

	// 6. Simulasi evaluasi
	input := rba.AssessmentInput{
		SubjectID:  "user-123",
		TenantID:   "tenant-a",
		RequestID:  "req-789",
		OccurredAt: time.Now().UTC(),
		Action:     "login",
		IPAddress:  "203.0.113.10",
		UserAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		Headers: map[string]string{
			"X-Device-ID": "device-familiar-hash",
		},
		Claims: map[string]any{
			"amr": []string{"pwd"},
		},
	}

	assessment, decision, err := assessor.Evaluate(ctx, input)
	if err != nil {
		log.Fatalf("evaluation failed: %v", err)
	}

	fmt.Printf("Risk Score:  %.2f\n", assessment.Score)
	fmt.Printf("Risk Level:  %s\n", assessment.Level)
	fmt.Printf("Decision:    %s\n", decision.Action)
	fmt.Printf("Reasons:     %d\n", len(assessment.Reasons))

	for _, r := range assessment.Reasons {
		fmt.Printf("  - [%s] %s\n", r.Code, r.Message)
	}

	switch decision.Action {
	case rba.DecisionAllow:
		fmt.Println("→ Allow: issue session/token")
	case rba.DecisionChallenge:
		fmt.Printf("→ Challenge: require %s step-up (min_acr=%s)\n",
			decision.Challenge.Type, decision.Challenge.MinAcr)
	case rba.DecisionDeny:
		fmt.Printf("→ Deny: %s\n", decision.DenyReason)
	}
}
