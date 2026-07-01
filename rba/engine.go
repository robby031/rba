package rba

import "context"

// SignalCollector mengumpulkan signal mentah dari request context.
//
// Nama collector harus unik dan stabil karena dipakai untuk
// observability dan debugging.
type SignalCollector interface {
	Name() string
	Collect(ctx context.Context, in AssessmentInput) ([]Signal, error)
}

// FeatureBuilder mengubah satu atau lebih signal menjadi feature
// yang stabil dan terverifikasi.
type FeatureBuilder interface {
	Build(ctx context.Context, in AssessmentInput, signals []Signal) ([]Feature, error)
}

// RiskEngine menghitung risk score dan risk level berdasarkan feature
// yang sudah dibangun.
type RiskEngine interface {
	Assess(ctx context.Context, in AssessmentInput, features []Feature) (Assessment, error)
}

// PolicyEngine memutuskan tindakan berdasarkan hasil assessment.
//
// PolicyEngine memisahkan logika keputusan bisnis dari kalkulasi risiko,
// sehingga perubahan threshold atau aturan tidak memaksa rewrite risk engine.
type PolicyEngine interface {
	Decide(ctx context.Context, in AssessmentInput, a Assessment) (Decision, error)
}

// Assessor adalah orchestrator utama yang mengoordinasikan alur RBA:
// koleksi signal -> pembangunan feature -> kalkulasi risiko -> keputusan policy.
type Assessor struct {
	collectors     []SignalCollector
	featureBuilder FeatureBuilder
	riskEngine     RiskEngine
	policyEngine   PolicyEngine
}

// NewAssessor membuat Assessor baru dengan komponen-komponen yang diberikan.
//
// Parameter collectors boleh nil atau kosong; dalam kasus tersebut
// Assessor akan tetap berjalan tanpa signal tambahan.
func NewAssessor(
	collectors []SignalCollector,
	featureBuilder FeatureBuilder,
	riskEngine RiskEngine,
	policyEngine PolicyEngine,
) *Assessor {
	if collectors == nil {
		collectors = []SignalCollector{}
	}
	if featureBuilder == nil {
		featureBuilder = nopFeatureBuilder{}
	}
	if riskEngine == nil {
		riskEngine = nopRiskEngine{}
	}
	if policyEngine == nil {
		policyEngine = nopPolicyEngine{}
	}

	return &Assessor{
		collectors:     collectors,
		featureBuilder: featureBuilder,
		riskEngine:     riskEngine,
		policyEngine:   policyEngine,
	}
}

// Evaluate menjalankan seluruh alur RBA terhadap AssessmentInput dan
// mengembalikan Assessment beserta Decision.
//
// Error hanya dikembalikan jika terjadi kegagalan teknis (misalnya
// database tidak terjangkau). Keputusan bisnis always-challenge atau
// always-allow tetap direpresentasikan sebagai Decision, bukan error.
func (a *Assessor) Evaluate(ctx context.Context, in AssessmentInput) (Assessment, Decision, error) {
	// 1. Collect signals
	var allSignals []Signal
	for _, c := range a.collectors {
		signals, err := c.Collect(ctx, in)
		if err != nil {
			return Assessment{}, Decision{}, err
		}
		allSignals = append(allSignals, signals...)
	}

	// 2. Build features
	features, err := a.featureBuilder.Build(ctx, in, allSignals)
	if err != nil {
		return Assessment{}, Decision{}, err
	}

	// 3. Assess risk
	assessment, err := a.riskEngine.Assess(ctx, in, features)
	if err != nil {
		return Assessment{}, Decision{}, err
	}
	assessment.Signals = allSignals
	assessment.Features = features

	// 4. Decide policy
	decision, err := a.policyEngine.Decide(ctx, in, assessment)
	if err != nil {
		return Assessment{}, Decision{}, err
	}

	return assessment, decision, nil
}

// --- nop implementations (safe defaults) ---

type nopFeatureBuilder struct{}

func (nopFeatureBuilder) Build(_ context.Context, _ AssessmentInput, _ []Signal) ([]Feature, error) {
	return nil, nil
}

type nopRiskEngine struct{}

func (nopRiskEngine) Assess(_ context.Context, _ AssessmentInput, _ []Feature) (Assessment, error) {
	return Assessment{Score: 0, Level: RiskLow}, nil
}

type nopPolicyEngine struct{}

func (nopPolicyEngine) Decide(_ context.Context, _ AssessmentInput, _ Assessment) (Decision, error) {
	return Decision{Action: DecisionAllow}, nil
}
