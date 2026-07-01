package rba

import "errors"

var (
	// ErrSignalCollectionFailed terjadi ketika salah satu signal collector gagal.
	ErrSignalCollectionFailed = errors.New("rba: signal collection failed")

	// ErrFeatureBuildFailed terjadi ketika feature builder gagal memproses signal.
	ErrFeatureBuildFailed = errors.New("rba: feature build failed")

	// ErrRiskAssessmentFailed terjadi ketika risk engine gagal menghitung score.
	ErrRiskAssessmentFailed = errors.New("rba: risk assessment failed")

	// ErrPolicyDecisionFailed terjadi ketika policy engine gagal memutuskan tindakan.
	ErrPolicyDecisionFailed = errors.New("rba: policy decision failed")

	// ErrStoreOperationFailed terjadi ketika operasi storage gagal.
	ErrStoreOperationFailed = errors.New("rba: store operation failed")
)
