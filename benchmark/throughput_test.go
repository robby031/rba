package benchmark

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robby031/rba/rba"
	"github.com/robby031/rba/rba/feature"
	"github.com/robby031/rba/rba/policy"
	"github.com/robby031/rba/rba/risk"
	"github.com/robby031/rba/rba/signals"
)

// TestThroughput mengukur request per detik (RPS) di berbagai tingkat concurrency.
func TestThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	a := benchAssessor()
	nInputs := 256
	inputs := make([]rba.AssessmentInput, nInputs)
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

	levels := []int{1, 4, 16, 64, 256, 512}
	targetOps := 20_000

	for _, c := range levels {
		c := c
		t.Run(fmt.Sprintf("concurrency_%d", c), func(t *testing.T) {
			t.Parallel()
			var count atomic.Int64
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			var wg sync.WaitGroup
			start := time.Now()
			done := make(chan struct{})

			for range c {
				wg.Go(func() {
					subCtx := context.Background()
					for {
						select {
						case <-ctx.Done():
							return
						case <-done:
							return
						default:
							idx := int(count.Load()) % nInputs
							a.Evaluate(subCtx, inputs[idx])
							count.Add(1)
							if count.Load() >= int64(targetOps) {
								return
							}
						}
					}
				})
			}

			for {
				if count.Load() >= int64(targetOps) {
					break
				}
				if time.Since(start) >= 9*time.Second {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			close(done)
			wg.Wait()
			elapsed := time.Since(start)
			totalOps := count.Load()
			rps := float64(totalOps) / elapsed.Seconds()

			t.Logf("concurrency=%4d  ops=%6d  elapsed=%v  rps=%.0f  ns/op=%.0f",
				c, totalOps, elapsed.Round(time.Millisecond), rps, 1e9/rps,
			)

			if c == 1 && rps < 10_000 {
				t.Errorf("expected >= 10_000 RPS at concurrency=1, got %.0f", rps)
			}
		})
	}
}

// TestConcurrentSafety: 64 goroutine × 500 ops, pastikan tidak data race.
func TestConcurrentSafety(t *testing.T) {
	a := benchAssessor()
	inputs := make([]rba.AssessmentInput, 64)
	for i := range inputs {
		inputs[i] = rba.AssessmentInput{
			SubjectID:  fmt.Sprintf("user-%04d", i),
			TenantID:   "tenant-a",
			RequestID:  fmt.Sprintf("req-%04d", i),
			OccurredAt: time.Now().UTC(),
			Action:     "login",
			IPAddress:  "203.0.113.1",
			UserAgent:  "Mozilla/5.0",
		}
	}

	var (
		wg    sync.WaitGroup
		count atomic.Int64
	)
	nGoroutines := 64
	opsPerGoroutine := 500

	for range nGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for range opsPerGoroutine {
				idx := int(count.Load()) % len(inputs)
				_, _, err := a.Evaluate(ctx, inputs[idx])
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				count.Add(1)
			}
		}()
	}
	wg.Wait()

	expected := int64(nGoroutines * opsPerGoroutine)
	got := count.Load()
	if got != expected {
		t.Fatalf("expected %d evaluations, got %d", expected, got)
	}
}

// TestMemoryAllocation mengukur alokasi heap per operasi via -benchmem.
func TestMemoryAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx := context.Background()
	in := rba.AssessmentInput{
		SubjectID:  "user-alloc",
		TenantID:   "tenant-a",
		RequestID:  "req-alloc",
		OccurredAt: time.Now().UTC(),
		Action:     "login",
		IPAddress:  "203.0.113.1",
		UserAgent:  "Mozilla/5.0",
		Headers:    map[string]string{"X-Device-ID": "device-alloc"},
		Claims:     map[string]any{"amr": []string{"pwd"}},
	}

	ipC := signals.NewIPCollector()
	uaC := signals.NewUserAgentCollector()
	devC := signals.NewDeviceCollector("X-Device-ID")
	fb := feature.NewDefaultBuilder()
	re := risk.NewRuleBasedEngine()
	pe := policy.NewRuleBasedEngine(nil)

	collectAll := func() []rba.Signal {
		var s []rba.Signal
		s1, _ := ipC.Collect(ctx, in)
		s2, _ := uaC.Collect(ctx, in)
		s3, _ := devC.Collect(ctx, in)
		s = append(s, s1...)
		s = append(s, s2...)
		s = append(s, s3...)
		return s
	}

	tests := []struct {
		name string
		fn   func()
	}{
		{"IPCollector", func() { ipC.Collect(ctx, in) }},
		{"UserAgentCollector", func() { uaC.Collect(ctx, in) }},
		{"DeviceCollector", func() { devC.Collect(ctx, in) }},
		{"FeatureBuilder", func() { fb.Build(ctx, in, collectAll()) }},
		{"RiskEngine", func() {
			re.Assess(ctx, in, []rba.Feature{
				{Name: "is_new_device", Value: true},
				{Name: "is_new_country", Value: true},
			})
		}},
		{"PolicyEngine", func() {
			pe.Decide(ctx, in, rba.Assessment{Score: 50, Level: rba.RiskMedium})
		}},
		{"Assessor_Evaluate", func() { benchAssessor().Evaluate(ctx, in) }},
	}

	t.Logf("%-24s %10s %12s %12s", "Component", "b.N", "Bytes/op", "Allocs/op")
	t.Log("------")
	for _, tt := range tests {
		br := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tt.fn()
			}
		})
		t.Logf("%-24s %10d %12d %12d",
			tt.name, br.N, br.AllocedBytesPerOp(), br.AllocsPerOp())
	}
}

// TestMinLatency mengukur latensi minimum (best case) secara manual.
func TestMinLatency(t *testing.T) {
	ctx := context.Background()
	in := benchInput()

	tests := []struct {
		name string
		a    *rba.Assessor
	}{
		{"baseline (nop)", rba.NewAssessor(nil, nil, nil, nil)},
		{"full pipeline", benchAssessor()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 100 {
				tt.a.Evaluate(ctx, in)
			}
			n := 1000
			var total time.Duration
			var min time.Duration = math.MaxInt64
			var max time.Duration

			for range n {
				start := time.Now()
				tt.a.Evaluate(ctx, in)
				elapsed := time.Since(start)
				total += elapsed
				if elapsed < min {
					min = elapsed
				}
				if elapsed > max {
					max = elapsed
				}
			}

			avg := total / time.Duration(n)
			t.Logf("calls=%5d  min=%8s  avg=%8s  max=%8s  total=%8s",
				n, min.Round(time.Microsecond), avg.Round(time.Microsecond),
				max.Round(time.Microsecond), total.Round(time.Millisecond))
		})
	}
}

// TestLinearScaling mengukur rasio degradasi saat collector/rules bertambah.
func TestLinearScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	ctx := context.Background()
	base := rba.AssessmentInput{
		SubjectID:  "user-scale",
		TenantID:   "tenant-a",
		RequestID:  "req-scale",
		OccurredAt: time.Now().UTC(),
		Action:     "login",
		IPAddress:  "203.0.113.1",
		UserAgent:  "Mozilla/5.0",
	}

	t.Run("collectors", func(t *testing.T) {
		sizes := []int{1, 5, 10, 25}
		var prev float64
		for _, n := range sizes {
			cc := make([]rba.SignalCollector, n)
			for i := range n {
				cc[i] = signals.NewIPCollector()
			}
			a := rba.NewAssessor(
				cc, feature.NewDefaultBuilder(),
				risk.NewRuleBasedEngine(), policy.NewRuleBasedEngine(nil),
			)
			br := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					a.Evaluate(ctx, base)
				}
			})
			nsOp := float64(br.NsPerOp())
			ratio := 1.0
			if prev > 0 {
				ratio = nsOp / prev
			}
			t.Logf("collectors=%3d  ns/op=%10.0f  ratio=%.2f", n, nsOp, ratio)
			prev = nsOp
		}
	})

	t.Run("rules", func(t *testing.T) {
		for _, n := range []int{1, 10, 50, 200, 1000} {
			rules := make([]rba.PolicyRule, n)
			for i := range n {
				rules[i] = rba.PolicyRule{
					Name: fmt.Sprintf("rule-%d", i), Priority: i,
					When: map[string]any{"risk_level": "critical"}, ThenAction: "deny",
				}
			}
			rules[n-1] = rba.PolicyRule{
				Name: "catch-all", Priority: n,
				When: map[string]any{"risk_level": "low"}, ThenAction: "allow",
			}
			a := rba.NewAssessor(
				[]rba.SignalCollector{signals.NewIPCollector()},
				feature.NewDefaultBuilder(), risk.NewRuleBasedEngine(),
				policy.NewRuleBasedEngine(&rba.PolicyBundle{Version: "v1", Rules: rules}),
			)
			br := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					a.Evaluate(ctx, base)
				}
			})
			t.Logf("rules=%5d  ns/op=%10.0f", n, float64(br.NsPerOp()))
		}
	})
}
