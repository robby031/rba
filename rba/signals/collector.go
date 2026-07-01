// Package signals menyediakan implementasi SignalCollector untuk mengumpulkan
// sinyal mentah dari request context.
//
// Collector bawaan mencakup IP address, User-Agent, dan device identifier.
// Semua collector mengikuti interface rba.SignalCollector dan dapat dikomposisikan.
package signals

import (
	"context"
	"net"
	"strings"

	"github.com/robby031/rba/rba"
)

// IPCollector mengumpulkan sinyal dari alamat IP pengirim.
//
// Sinyal yang dihasilkan:
//   - "ip.address": alamat IP mentah
//   - "ip.is_private": apakah IP termasuk private/reserved range
//   - "ip.version": 4 atau 6
type IPCollector struct{}

func NewIPCollector() *IPCollector {
	return &IPCollector{}
}

func (c *IPCollector) Name() string { return "ip" }

func (c *IPCollector) Collect(_ context.Context, in rba.AssessmentInput) ([]rba.Signal, error) {
	if in.IPAddress == "" {
		return nil, nil
	}

	signals := []rba.Signal{
		{Name: "ip.address", Value: in.IPAddress, Confidence: 1.0, Source: "request"},
	}

	ip := net.ParseIP(in.IPAddress)
	if ip != nil {
		isPrivate := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
		signals = append(signals, rba.Signal{
			Name:       "ip.is_private",
			Value:      isPrivate,
			Confidence: 1.0,
			Source:     "request",
		})

		version := 4
		if strings.Contains(in.IPAddress, ":") {
			version = 6
		}
		signals = append(signals, rba.Signal{
			Name:       "ip.version",
			Value:      version,
			Confidence: 1.0,
			Source:     "request",
		})
	}

	return signals, nil
}

// UserAgentCollector mengumpulkan sinyal dari User-Agent header.
//
// Sinyal yang dihasilkan:
//   - "ua.raw": user-agent mentah
//   - "ua.is_empty": apakah user-agent kosong (mencurigakan)
type UserAgentCollector struct{}

func NewUserAgentCollector() *UserAgentCollector {
	return &UserAgentCollector{}
}

func (c *UserAgentCollector) Name() string { return "user_agent" }

func (c *UserAgentCollector) Collect(_ context.Context, in rba.AssessmentInput) ([]rba.Signal, error) {
	signals := []rba.Signal{
		{Name: "ua.raw", Value: in.UserAgent, Confidence: 0.8, Source: "request"},
		{Name: "ua.is_empty", Value: in.UserAgent == "", Confidence: 1.0, Source: "request"},
	}
	return signals, nil
}

// DeviceCollector mengumpulkan sinyal dari device identifier,
// biasanya berasal dari cookie atau header khusus.
//
// Sinyal yang dihasilkan:
//   - "device.id": device identifier hash
//   - "device.is_known": akan diisi oleh feature builder berdasarkan histori
type DeviceCollector struct {
	headerName string
}

// NewDeviceCollector membuat collector yang membaca device ID dari header.
// Jika headerName kosong, default "X-Device-ID" digunakan.
func NewDeviceCollector(headerName string) *DeviceCollector {
	if headerName == "" {
		headerName = "X-Device-ID"
	}
	return &DeviceCollector{headerName: headerName}
}

func (c *DeviceCollector) Name() string { return "device" }

func (c *DeviceCollector) Collect(_ context.Context, in rba.AssessmentInput) ([]rba.Signal, error) {
	deviceID := ""
	if in.Headers != nil {
		deviceID = in.Headers[c.headerName]
	}
	if deviceID == "" {
		// Fallback: coba header dengan huruf kecil
		if in.Headers != nil {
			deviceID = in.Headers[strings.ToLower(c.headerName)]
		}
	}
	if deviceID == "" {
		return nil, nil
	}

	return []rba.Signal{
		{Name: "device.id", Value: deviceID, Confidence: 0.9, Source: "request"},
	}, nil
}

// CompositeCollector menggabungkan beberapa collector menjadi satu.
// Berguna untuk mengelompokkan collector yang selalu dipakai bersama.
type CompositeCollector struct {
	name       string
	collectors []rba.SignalCollector
}

func NewCompositeCollector(name string, collectors ...rba.SignalCollector) *CompositeCollector {
	return &CompositeCollector{
		name:       name,
		collectors: collectors,
	}
}

func (c *CompositeCollector) Name() string { return c.name }

func (c *CompositeCollector) Collect(ctx context.Context, in rba.AssessmentInput) ([]rba.Signal, error) {
	var all []rba.Signal
	for _, col := range c.collectors {
		signals, err := col.Collect(ctx, in)
		if err != nil {
			return nil, err
		}
		all = append(all, signals...)
	}
	return all, nil
}
