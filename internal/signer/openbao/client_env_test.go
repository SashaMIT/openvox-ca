// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package openbao

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openbao/openbao/api/v2"
)

// newClient reports the SDK environment variables it was built under. Every
// spec starts from an environment with none of them, whatever the developer's
// or CI's shell holds, and sets only what it is about.
var _ = Describe("newClient's report of the OpenBao environment", func() {
	var (
		buf bytes.Buffer
		cfg Config
	)

	// unset removes name for this spec only: GinkgoT().Setenv records the
	// original value for restoration, and the Unsetenv that follows makes it
	// absent rather than empty — an empty BAO_ variable is not the same as a
	// missing one to the SDK, since it masks the VAULT_ fallback.
	unset := func(name string) {
		GinkgoT().Setenv(name, "")
		Expect(os.Unsetenv(name)).To(Succeed())
	}

	BeforeEach(func() {
		names := []string{api.EnvVaultSkipVerify}
		for _, v := range envVariables {
			names = append(names, v.name)
		}
		for _, n := range names {
			unset(n)
			unset(api.UpstreamVariableName(n))
		}

		buf.Reset()
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		DeferCleanup(func() { slog.SetDefault(orig) })

		cfg = Config{Addr: "https://openbao.invalid:8200", AuthMethod: AuthAppRole}
	})

	build := func() {
		_, err := newClient(cfg)
		Expect(err).NotTo(HaveOccurred())
	}

	// writeCA writes a self-signed CA certificate for openbao.tls_ca_file.
	// ConfigureTLS only needs to parse it; nothing connects.
	writeCA := func() string {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "openbao test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		path := filepath.Join(GinkgoT().TempDir(), "ca.pem")
		Expect(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)).To(Succeed())
		return path
	}

	It("logs nothing when no variable is set", func() {
		build()
		Expect(buf.String()).To(BeEmpty(),
			"a warning on every clean start is noise, and noise is how a real one stops being read")
	})

	// skipVerifyLine matches the start of the dedicated record, so a generic
	// "taken from the environment" warning cannot satisfy these specs.
	const skipVerifyLine = `level=WARN msg="OpenBao server certificate verification is OFF[^"]*" `

	Context("when server certificate verification is switched off", func() {
		It("reports BAO_SKIP_VERIFY on a warning line of its own", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "true")
			build()
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=BAO_SKIP_VERIFY`))
			Expect(buf.String()).NotTo(ContainSubstring("level=ERROR"),
				"warning level, so it does not trip alerting keyed on errors")
		})

		It("reports VAULT_SKIP_VERIFY under its own name", func() {
			GinkgoT().Setenv("VAULT_SKIP_VERIFY", "true")
			build()
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=VAULT_SKIP_VERIFY`))
		})

		// The configured CA file cannot turn verification back on: the SDK's
		// ConfigureTLS only ever sets InsecureSkipVerify, never clears it.
		It("still reports it when openbao.tls_ca_file is set, naming what it overrides", func() {
			cfg.TLSCAFile = writeCA()
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "1")
			build()
			Expect(buf.String()).To(MatchRegexp(skipVerifyLine + `variable=BAO_SKIP_VERIFY overrides=openbao\.tls_ca_file`))
		})
	})

	Context("when a SKIP_VERIFY variable leaves verification on", func() {
		It("stays quiet for an explicit false", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "false")
			build()
			Expect(buf.String()).To(BeEmpty())
		})

		// The SDK reads a present BAO_ variable even when it is empty, which
		// masks the VAULT_ one; the report must follow that reading.
		It("stays quiet when an empty BAO_SKIP_VERIFY masks VAULT_SKIP_VERIFY", func() {
			GinkgoT().Setenv("BAO_SKIP_VERIFY", "")
			GinkgoT().Setenv("VAULT_SKIP_VERIFY", "true")
			build()
			Expect(buf.String()).To(BeEmpty())
		})
	})

	It("warns about a proxy by name, without logging its value", func() {
		GinkgoT().Setenv("BAO_PROXY_ADDR", "http://proxyuser:proxy-secret@proxy.invalid:3128")
		build()
		Expect(buf.String()).To(ContainSubstring("level=WARN"))
		Expect(buf.String()).To(ContainSubstring("variable=BAO_PROXY_ADDR"))
		Expect(buf.String()).NotTo(ContainSubstring("proxy-secret"))
		Expect(buf.String()).NotTo(ContainSubstring("proxy.invalid"))
	})

	It("warns about BAO_TOKEN by name, without logging the token", func() {
		GinkgoT().Setenv("BAO_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(ContainSubstring("level=WARN"))
		Expect(buf.String()).To(ContainSubstring("variable=BAO_TOKEN"))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	// With token auth the token file is set on the client before the first
	// request, so an ambient token is never sent.
	It("reports BAO_TOKEN as superseded under token auth, without logging the token", func() {
		cfg.AuthMethod = AuthToken
		GinkgoT().Setenv("VAULT_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(ContainSubstring("level=INFO"))
		Expect(buf.String()).To(ContainSubstring("variable=VAULT_TOKEN"))
		Expect(buf.String()).To(ContainSubstring("superseded_by=openbao.token_file"))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	It("reports BAO_ADDR as superseded by openbao.addr, not as an override", func() {
		GinkgoT().Setenv("BAO_ADDR", "https://elsewhere.invalid:8200")
		build()
		Expect(buf.String()).To(ContainSubstring("level=INFO"))
		Expect(buf.String()).To(ContainSubstring("variable=BAO_ADDR"))
		Expect(buf.String()).To(ContainSubstring("superseded_by=openbao.addr"))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("elsewhere.invalid"))
	})

	// BAO_AGENT_ADDR is the address variable that does win: NewClient sends
	// every request to AgentAddress when it is set, and openvox-ca only sets
	// Address.
	It("warns that BAO_AGENT_ADDR overrides openbao.addr", func() {
		GinkgoT().Setenv("BAO_AGENT_ADDR", "https://agent.invalid:8100")
		build()
		Expect(buf.String()).To(ContainSubstring("level=WARN"))
		Expect(buf.String()).To(ContainSubstring("variable=BAO_AGENT_ADDR"))
		Expect(buf.String()).To(ContainSubstring("overrides=openbao.addr"))
	})

	Context("with a CA from the environment", func() {
		BeforeEach(func() {
			GinkgoT().Setenv("BAO_CACERT", writeCA())
		})

		It("warns when openbao.tls_ca_file is unset", func() {
			build()
			Expect(buf.String()).To(ContainSubstring("level=WARN"))
			Expect(buf.String()).To(ContainSubstring("variable=BAO_CACERT"))
		})

		It("reports it as superseded when openbao.tls_ca_file is set", func() {
			cfg.TLSCAFile = writeCA()
			build()
			Expect(buf.String()).To(ContainSubstring("superseded_by=openbao.tls_ca_file"))
			Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		})
	})

	It("ignores a variable set to the empty string, as the SDK does", func() {
		GinkgoT().Setenv("BAO_NAMESPACE", "")
		GinkgoT().Setenv("VAULT_NAMESPACE", "team-a")
		build()
		Expect(buf.String()).To(BeEmpty())
	})
})
