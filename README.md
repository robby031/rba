# rba - Risk-Based Authentication

**rba** is a Go library for Risk-Based Authentication (RBA) designed as an inline decisioning layer - evaluating the context of a login or access request (device, IP, geolocation, behavioral history, action sensitivity) and determining whether the session should be allowed, require step-up authentication, or be blocked.

## Architecture

```
Signal Collectors -> Feature Builder -> Risk Engine -> Policy Engine
Storage Adapters:
- EventStore
- SessionStore
- ProfileStore
- PolicyStore
```

## Package structure

```
rba/                     # Core types + Assessor orchestrator
rba/signals/             # Signal collectors (IP, UA, device, geo)
rba/feature/             # Feature builder (signal -> feature)
rba/risk/                # Risk engine (feature -> score + level)
rba/policy/              # Policy engine (assessment -> decision)
rba/storage/             # Storage adapter interfaces
rba/oidc/                # OIDC claims mapper + step-up helper
rba/telemetry/           # Observability hooks & interfaces
```

## Quick start

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/robby031/rba/rba"
    "github.com/robby031/rba/rba/feature"
    "github.com/robby031/rba/rba/policy"
    "github.com/robby031/rba/rba/risk"
    "github.com/robby031/rba/rba/signals"
)

func main() {
    collectors := []rba.SignalCollector{
        signals.NewIPCollector(),
        signals.NewUserAgentCollector(),
        signals.NewDeviceCollector("X-Device-ID"),
    }

    assessor := rba.NewAssessor(
        collectors,
        feature.NewDefaultBuilder(),
        risk.NewRuleBasedEngine(),
        policy.NewRuleBasedEngine(nil),
    )

    input := rba.AssessmentInput{
        SubjectID:  "user-123",
        TenantID:   "tenant-a",
        RequestID:  "req-789",
        OccurredAt: time.Now().UTC(),
        Action:     "login",
        IPAddress:  "203.0.113.10",
        UserAgent:  "Mozilla/5.0",
    }

    assessment, decision, err := assessor.Evaluate(context.Background(), input)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("risk=%s score=%.2f decision=%s",
        assessment.Level, assessment.Score, decision.Action)
}
```

See [examples/main.go](./examples/main.go) for a complete example.

## Design principles

1. **Library-first, synchronous inline** - risk decisions are made synchronously within the login flow.
2. **Pluggable adapters** - storage, collectors, and the policy engine can be replaced.
3. **Minimal dependencies** - only the Go standard library (`go 1.26.4`).
4. **Explainable decisions** - every decision includes reason codes.
5. **Separation of risk calculation and policy decision** - changing thresholds does not require rewriting the risk engine.
