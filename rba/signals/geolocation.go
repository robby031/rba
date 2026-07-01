package signals

import (
	"context"

	"github.com/robby031/rba/rba"
)

// GeoIPResolver adalah antarmuka untuk resolver geolokasi dari alamat IP.
// Implementasi dapat menggunakan database GeoLite2, layanan eksternal, atau
// stub untuk pengujian.
type GeoIPResolver interface {
	// Resolve mengembalikan kode negara (ISO 3166-1 alpha-2) untuk IP yang diberikan.
	// String kosong dikembalikan jika IP tidak dapat di-resolve.
	Resolve(ctx context.Context, ip string) (country string, asn string, err error)
}

// GeoIPCollector mengumpulkan sinyal geolokasi dari alamat IP menggunakan GeoIPResolver.
//
// Sinyal yang dihasilkan:
//   - "geo.country": kode negara ISO 3166-1 alpha-2
//   - "geo.asn": Autonomous System Number
type GeoIPCollector struct {
	resolver GeoIPResolver
}

func NewGeoIPCollector(resolver GeoIPResolver) *GeoIPCollector {
	return &GeoIPCollector{resolver: resolver}
}

func (c *GeoIPCollector) Name() string { return "geoip" }

func (c *GeoIPCollector) Collect(ctx context.Context, in rba.AssessmentInput) ([]rba.Signal, error) {
	if in.IPAddress == "" || c.resolver == nil {
		return nil, nil
	}

	country, asn, err := c.resolver.Resolve(ctx, in.IPAddress)
	if err != nil {
		return nil, err
	}

	var signals []rba.Signal
	if country != "" {
		signals = append(signals, rba.Signal{
			Name:       "geo.country",
			Value:      country,
			Confidence: 0.7,
			Source:     "geoip",
		})
	}
	if asn != "" {
		signals = append(signals, rba.Signal{
			Name:       "geo.asn",
			Value:      asn,
			Confidence: 0.7,
			Source:     "geoip",
		})
	}

	return signals, nil
}
