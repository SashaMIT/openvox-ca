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
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openbao/openbao/api/v2"
)

// reportedNames is every variable logEnvironment can report: the
// envVariables table plus BAO_SKIP_VERIFY, which has a line of its own.
func reportedNames() []string {
	names := []string{api.EnvVaultSkipVerify}
	for _, v := range envVariables {
		names = append(names, v.name)
	}
	sort.Strings(names)
	return names
}

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
		for _, n := range reportedNames() {
			unset(n)
			unset(api.UpstreamVariableName(n))
		}

		buf.Reset()
		// slog.SetDefault also points the log package at the new handler, and
		// restoring the original handler does not undo that, so restore the
		// log package's writer and flags as well.
		orig, origWriter, origFlags := slog.Default(), log.Writer(), log.Flags()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		DeferCleanup(func() {
			slog.SetDefault(orig)
			log.SetOutput(origWriter)
			log.SetFlags(origFlags)
		})

		cfg = Config{Addr: "https://openbao.invalid:8200", AuthMethod: AuthAppRole}
	})

	build := func() *api.Client {
		client, err := newClient(cfg)
		Expect(err).NotTo(HaveOccurred())
		return client
	}

	// warnLine and infoLine match a whole generic record, so a line with the
	// right variable under the wrong message, or without its effect, fails.
	warnLine := func(variable string) string {
		return `level=WARN msg="OpenBao client setting taken from the environment" variable=` +
			regexp.QuoteMeta(variable) + ` effect="[^"]+"`
	}
	infoLine := func(variable, setting string) string {
		return `level=INFO msg="OpenBao environment variable has no effect" variable=` +
			regexp.QuoteMeta(variable) + ` superseded_by=` + regexp.QuoteMeta(setting) + `\n`
	}

	// newCert returns a self-signed certificate and its key. ConfigureTLS
	// only needs to parse what it is given; nothing connects.
	newCert := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert, key
	}

	writePEM := func(name, blockType string, der []byte) string {
		path := filepath.Join(GinkgoT().TempDir(), name)
		Expect(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600)).To(Succeed())
		return path
	}

	// writeCA writes a fresh CA certificate and returns its path and the
	// certificate itself.
	writeCA := func() (string, *x509.Certificate) {
		cert, _ := newCert("openbao test CA")
		return writePEM("ca.pem", "CERTIFICATE", cert.Raw), cert
	}

	// writeKeyPair writes a client certificate and key and returns their paths.
	writeKeyPair := func() (string, string) {
		cert, key := newCert("openbao test client")
		der, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		return writePEM("client.pem", "CERTIFICATE", cert.Raw), writePEM("client.key", "PRIVATE KEY", der)
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
			cfg.TLSCAFile, _ = writeCA()
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
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_PROXY_ADDR")))
		Expect(buf.String()).NotTo(ContainSubstring("proxy-secret"))
		Expect(buf.String()).NotTo(ContainSubstring("proxy.invalid"))
	})

	It("warns about BAO_TOKEN by name, without logging the token", func() {
		GinkgoT().Setenv("BAO_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_TOKEN")))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	// With token auth the token file is set on the client before the first
	// request, so an ambient token is never sent.
	It("reports BAO_TOKEN as superseded under token auth, without logging the token", func() {
		cfg.AuthMethod = AuthToken
		GinkgoT().Setenv("VAULT_TOKEN", "s.ambient-token-value")
		build()
		Expect(buf.String()).To(MatchRegexp(infoLine("VAULT_TOKEN", "openbao.token_file")))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("ambient-token-value"))
	})

	It("reports BAO_ADDR as superseded by openbao.addr, not as an override", func() {
		GinkgoT().Setenv("BAO_ADDR", "https://elsewhere.invalid:8200")
		build()
		Expect(buf.String()).To(MatchRegexp(infoLine("BAO_ADDR", "openbao.addr")))
		Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		Expect(buf.String()).NotTo(ContainSubstring("elsewhere.invalid"))
	})

	// BAO_AGENT_ADDR is the address variable that does win: NewClient sends
	// every request to AgentAddress when it is set, and openvox-ca only sets
	// Address.
	It("warns that BAO_AGENT_ADDR overrides openbao.addr", func() {
		GinkgoT().Setenv("BAO_AGENT_ADDR", "https://agent.invalid:8100")
		build()
		Expect(buf.String()).To(MatchRegexp(warnLine("BAO_AGENT_ADDR") + ` overrides=openbao\.addr`))
	})

	// The supersession is a prediction made from cfg alone, so each case
	// also checks the trust pool of the client that was actually built: if
	// the SDK ever merged the pools instead of rebuilding them, the log line
	// would be wrong and these specs would say so.
	Context("with a CA from the environment", func() {
		var envCA *x509.Certificate

		BeforeEach(func() {
			var path string
			path, envCA = writeCA()
			GinkgoT().Setenv("BAO_CACERT", path)
		})

		trusts := func(client *api.Client) bool {
			_, err := envCA.Verify(x509.VerifyOptions{Roots: client.CloneConfig().TLSConfig().RootCAs})
			return err == nil
		}

		It("warns, and trusts that CA, when openbao.tls_ca_file is unset", func() {
			client := build()
			Expect(buf.String()).To(MatchRegexp(warnLine("BAO_CACERT")))
			Expect(trusts(client)).To(BeTrue())
		})

		It("reports it as superseded, and no longer trusts it, when openbao.tls_ca_file is set", func() {
			cfg.TLSCAFile, _ = writeCA()
			client := build()
			Expect(buf.String()).To(MatchRegexp(infoLine("BAO_CACERT", "openbao.tls_ca_file")))
			Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
			Expect(trusts(client)).To(BeFalse())
		})
	})

	Context("with a client certificate from the environment", func() {
		BeforeEach(func() {
			certPath, keyPath := writeKeyPair()
			GinkgoT().Setenv("BAO_CLIENT_CERT", certPath)
			GinkgoT().Setenv("BAO_CLIENT_KEY", keyPath)
		})

		It("warns when openvox-ca configures no TLS files", func() {
			build()
			Expect(buf.String()).To(MatchRegexp(warnLine("BAO_CLIENT_CERT")))
			Expect(buf.String()).To(MatchRegexp(warnLine("BAO_CLIENT_KEY")))
		})

		// ConfigureTLS replaces the client certificate only when it is given
		// one, so a CA file alone leaves the environment's certificate in use.
		It("still warns when only openbao.tls_ca_file is set", func() {
			cfg.TLSCAFile, _ = writeCA()
			build()
			Expect(buf.String()).To(MatchRegexp(warnLine("BAO_CLIENT_CERT")))
			Expect(buf.String()).To(MatchRegexp(warnLine("BAO_CLIENT_KEY")))
		})

		It("reports it as superseded when openbao.tls_cert_file and tls_key_file are set", func() {
			cfg.TLSCertFile, cfg.TLSKeyFile = writeKeyPair()
			build()
			Expect(buf.String()).To(MatchRegexp(infoLine("BAO_CLIENT_CERT", "openbao.tls_cert_file")))
			Expect(buf.String()).To(MatchRegexp(infoLine("BAO_CLIENT_KEY", "openbao.tls_cert_file")))
			Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		})
	})

	// These two are read from the SDK's resulting config rather than the
	// raw value, so a value that leaves the default in place stays quiet.
	DescribeTable("a boolean variable",
		func(name, value string, warns bool) {
			GinkgoT().Setenv(name, value)
			build()
			if warns {
				Expect(buf.String()).To(MatchRegexp(warnLine(name)))
			} else {
				Expect(buf.String()).To(BeEmpty())
			}
		},
		Entry("BAO_SRV_LOOKUP=true warns", "BAO_SRV_LOOKUP", "true", true),
		Entry("BAO_SRV_LOOKUP=false stays quiet", "BAO_SRV_LOOKUP", "false", false),
		Entry("BAO_DISABLE_REDIRECTS=true warns", "BAO_DISABLE_REDIRECTS", "true", true),
		Entry("BAO_DISABLE_REDIRECTS=false stays quiet", "BAO_DISABLE_REDIRECTS", "false", false),
	)

	It("ignores a variable set to the empty string, as the SDK does", func() {
		GinkgoT().Setenv("BAO_NAMESPACE", "")
		GinkgoT().Setenv("VAULT_NAMESPACE", "team-a")
		build()
		Expect(buf.String()).To(BeEmpty())
	})

	// The SDK's own message for this case says nothing about the
	// environment, so without the names an operator has nowhere to look.
	It("names the variables set, without their values, when the environment stops the client being built", func() {
		certPath, _ := writeKeyPair()
		GinkgoT().Setenv("VAULT_CLIENT_CERT", certPath)
		_, err := newClient(cfg)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("OpenBao environment variables set: VAULT_CLIENT_CERT"))
		Expect(err.Error()).NotTo(ContainSubstring(certPath))
	})
})

// The operator-facing table and envVariables both enumerate what the SDK
// reads. These specs hold the three in step, so an SDK upgrade that starts
// reading another variable fails here rather than going unreported.
var _ = Describe("the OpenBao environment enumeration", func() {
	It("matches the table in docs/openbao-transit.md", func() {
		doc, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "openbao-transit.md"))
		Expect(err).NotTo(HaveOccurred())

		_, section, found := strings.Cut(string(doc), "\n### OpenBao client environment variables\n")
		Expect(found).To(BeTrue(), "the section heading moved; update this spec and the anchor in client.go")
		section, _, _ = strings.Cut(section, "\n#")

		var documented []string
		name := regexp.MustCompile("`(BAO_[A-Z_]+)`")
		for _, line := range strings.Split(section, "\n") {
			if !strings.HasPrefix(line, "| `BAO_") {
				continue
			}
			firstCell := strings.Split(line, "|")[1]
			for _, m := range name.FindAllStringSubmatch(firstCell, -1) {
				documented = append(documented, m[1])
			}
		}
		sort.Strings(documented)
		Expect(documented).To(Equal(reportedNames()))
	})

	It("matches every ReadBaoVariable call in the SDK source go.mod pins", func() {
		dir := sdkSourceDir()

		// Read by plugin_helpers.go, which only OpenBao plugins call; the
		// client newClient builds never reaches it.
		pluginOnly := map[string]bool{
			"BAO_PLUGIN_AUTOMTLS_ENABLED": true,
			"BAO_PLUGIN_METADATA_MODE":    true,
			"BAO_UNWRAP_TOKEN":            true,
		}

		fset := token.NewFileSet()
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		Expect(err).NotTo(HaveOccurred())
		consts := map[string]string{}
		var parsed []*ast.File
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			Expect(err).NotTo(HaveOccurred())
			parsed = append(parsed, file)
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if i < len(vs.Values) {
							if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
								consts[id.Name], _ = strconv.Unquote(lit.Value)
							}
						}
					}
				}
			}
		}
		Expect(consts).NotTo(BeEmpty(), "found no constants under %s", dir)

		read := map[string]bool{}
		for _, file := range parsed {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || (fn.Name != "ReadBaoVariable" && fn.Name != "LookupBaoVariable") {
					return true
				}
				switch arg := call.Args[0].(type) {
				case *ast.Ident:
					value, ok := consts[arg.Name]
					Expect(ok).To(BeTrue(), "%s reads %s, which this spec cannot resolve", fset.Position(call.Pos()), arg.Name)
					read[value] = true
				case *ast.BasicLit:
					value, _ := strconv.Unquote(arg.Value)
					read[value] = true
				default:
					Fail("cannot resolve the argument to " + fn.Name + " at " + fset.Position(call.Pos()).String())
				}
				return true
			})
		}

		var sdk []string
		for name := range read {
			if !pluginOnly[name] {
				sdk = append(sdk, name)
			}
		}
		sort.Strings(sdk)
		Expect(sdk).To(Equal(reportedNames()),
			"the SDK reads a different set of variables: update envVariables and the docs table together")
	})
})

// sdkSourceDir asks the go command where the pinned api/v2 module lives. Its
// environment has GIT_* stripped, as AGENTS.md requires of anything that
// might run git.
func sdkSourceDir() string {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openbao/openbao/api/v2")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.Output()
	Expect(err).NotTo(HaveOccurred())
	dir := strings.TrimSpace(string(out))
	Expect(dir).NotTo(BeEmpty())
	return dir
}
