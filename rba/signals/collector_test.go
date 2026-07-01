package signals

import (
	"context"
	"testing"

	"github.com/robby031/rba/rba"
)

func TestIPCollector_EmptyIP(t *testing.T) {
	c := NewIPCollector()
	in := rba.AssessmentInput{}

	signals, err := c.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected 0 signals for empty IP, got %d", len(signals))
	}
}

func TestIPCollector_ValidIPv4(t *testing.T) {
	c := NewIPCollector()
	in := rba.AssessmentInput{IPAddress: "203.0.113.10"}

	signals, err := c.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasIP, hasPrivate, hasVersion bool
	for _, s := range signals {
		switch s.Name {
		case "ip.address":
			hasIP = true
			if s.Value != "203.0.113.10" {
				t.Fatalf("unexpected ip value: %v", s.Value)
			}
		case "ip.is_private":
			hasPrivate = true
			if s.Value != false {
				t.Fatalf("expected public IP, got private=true")
			}
		case "ip.version":
			hasVersion = true
			if s.Value != 4 {
				t.Fatalf("expected version 4, got %v", s.Value)
			}
		}
	}
	if !hasIP || !hasPrivate || !hasVersion {
		t.Fatal("missing expected signals")
	}
}

func TestIPCollector_PrivateIP(t *testing.T) {
	c := NewIPCollector()
	in := rba.AssessmentInput{IPAddress: "10.0.0.1"}

	signals, err := c.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, s := range signals {
		if s.Name == "ip.is_private" && s.Value != true {
			t.Fatal("expected private IP detection")
		}
	}
}

func TestUserAgentCollector(t *testing.T) {
	c := NewUserAgentCollector()
	tests := []struct {
		name        string
		ua          string
		wantEmpty   bool
		wantSignals int
	}{
		{"empty UA", "", true, 2},
		{"valid UA", "Mozilla/5.0", false, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := rba.AssessmentInput{UserAgent: tt.ua}
			signals, err := c.Collect(context.Background(), in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(signals) != tt.wantSignals {
				t.Fatalf("expected %d signals, got %d", tt.wantSignals, len(signals))
			}
			for _, s := range signals {
				if s.Name == "ua.is_empty" && s.Value != tt.wantEmpty {
					t.Fatalf("expected ua.is_empty=%v, got %v", tt.wantEmpty, s.Value)
				}
			}
		})
	}
}

func TestDeviceCollector(t *testing.T) {
	c := NewDeviceCollector("X-Device-ID")
	in := rba.AssessmentInput{
		Headers: map[string]string{"X-Device-ID": "device-hash-123"},
	}

	signals, err := c.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].Name != "device.id" {
		t.Fatalf("expected device.id, got %s", signals[0].Name)
	}
	if signals[0].Value != "device-hash-123" {
		t.Fatalf("unexpected device ID: %v", signals[0].Value)
	}
}

func TestDeviceCollector_NoHeader(t *testing.T) {
	c := NewDeviceCollector("X-Device-ID")
	in := rba.AssessmentInput{}

	signals, err := c.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("expected 0 signals, got %d", len(signals))
	}
}

func TestCompositeCollector(t *testing.T) {
	ip := NewIPCollector()
	ua := NewUserAgentCollector()
	composite := NewCompositeCollector("request", ip, ua)

	in := rba.AssessmentInput{
		IPAddress: "1.2.3.4",
		UserAgent: "test-agent",
	}

	signals, err := composite.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// IP: 3 signals, UA: 2 signals = 5 total
	if len(signals) != 5 {
		t.Fatalf("expected 5 signals, got %d", len(signals))
	}
}
