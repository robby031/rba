// Package rba adalah library Risk-Based Authentication (RBA) untuk Go.
//
// RBA adalah lapisan decisioning yang menilai konteks login atau akses
// — misalnya perangkat, IP, geolokasi, histori perilaku, dan sensitivitas
// aksi — lalu menentukan apakah sesi boleh diteruskan, harus di-step-up,
// atau harus diblokir.
//
// # Arsitektur
//
// Library ini mengadopsi arsitektur modular dengan pemisahan tegas:
//
//   - rba/signals — SignalCollector untuk mengumpulkan sinyal mentah (IP, UA, device)
//   - rba/feature — FeatureBuilder untuk transformasi signal menjadi feature stabil
//   - rba/risk — RiskEngine untuk kalkulasi risk score dan risk level
//   - rba/policy — PolicyEngine untuk keputusan allow/challenge/deny
//   - rba/storage — Antarmuka adapter persistence (EventStore, SessionStore, dll)
//   - rba/oidc — Mapper hasil RBA ke klaim OIDC (acr, amr, auth_time)
//   - rba/telemetry — Antarmuka observability (hooks, metrics, logging)
//
// Alur evaluasi: Collect signals → Build features → Assess risk → Decide policy.
// Pemisahan ini memudahkan testing, explainability, dan backward compatibility.
//
// Prinsip desain
//
//  1. Library-first, synchronous inline evaluator — keputusan risiko dibuat
//     sinkron di jalur login/API.
//  2. Pluggable adapters — storage, signal collector, dan policy engine dapat
//     diganti tanpa mengubah core.
//  3. Minimal dependencies — hanya bergantung pada stdlib Go.
//  4. Explainable decisions — setiap keputusan disertai reason codes untuk
//     audit, tuning, dan debugging.
//
// Untuk contoh penggunaan lengkap, lihat direktori examples/.
package rba
