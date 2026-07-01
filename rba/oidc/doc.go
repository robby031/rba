// Package oidc menyediakan mapper untuk memproyeksikan hasil RBA ke
// klaim OIDC/OAuth (acr, amr, auth_time) serta helper untuk challenge
// step-up sesuai RFC 9470.
//
// Pemetaan yang didukung:
//   - Assurance saat ini   -> acr claim
//   - Metode autentikasi   -> amr claim
//   - Waktu autentikasi    -> auth_time claim
//   - Step-up challenge    -> RFC 9470 WWW-Authenticate header
package oidc
