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

//go:build postgres_integration

package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/uptrace/bun/driver/pgdriver"
)

// pgTestCA is a throwaway CA minted per spec, so no key is ever committed.
type pgTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newPGTestCA(name string) *pgTestCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return &pgTestCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issueServer returns a PEM certificate and key for a server answering to
// host, which may be a DNS name or an IP address.
func (ca *pgTestCA) issueServer(host string) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// servePostgresTLS switches the test server's TLS on with a certificate issued
// by ca for certHost, and back off when the spec ends. The fixture runs
// PostgreSQL without TLS, so this writes the files into the server's data
// directory and enables them with ALTER SYSTEM, which needs the DSN's role to
// be a superuser — as the compose fixture's is. It writes through COPY TO
// PROGRAM rather than COPY TO a file because only the former can set a umask:
// COPY creates files 0644, and PostgreSQL refuses a key anyone else can read.
func servePostgresTLS(dsn string, ca *pgTestCA, certHost string) {
	certPEM, keyPEM := ca.issueServer(certHost)
	db := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	DeferCleanup(db.Close)
	ctx := context.Background()

	var dataDir string
	Expect(db.QueryRowContext(ctx, "SHOW data_directory").Scan(&dataDir)).To(Succeed())
	// A name unique to this spec, so the wait below cannot be satisfied by an
	// earlier spec's configuration.
	stem := filepath.Join(dataDir, fmt.Sprintf("openvox-ca-test-%d", time.Now().UnixNano()))
	// Registered before anything changes, so a failure part-way through still
	// puts the server back. RESET of a setting never set is a no-op, as is
	// rm -f of a file never written.
	DeferCleanup(func() {
		for _, stmt := range []string{
			"ALTER SYSTEM RESET ssl",
			"ALTER SYSTEM RESET ssl_cert_file",
			"ALTER SYSTEM RESET ssl_key_file",
			"SELECT pg_reload_conf()",
			fmt.Sprintf("COPY (SELECT 1) TO PROGRAM 'rm -f %s.crt %s.key'", stem, stem),
		} {
			_, err := db.ExecContext(ctx, stmt)
			Expect(err).NotTo(HaveOccurred(), stmt)
		}
	})
	write := func(path string, content []byte) {
		// COPY's text format escapes newlines inside a value, so write one
		// row per line. PEM lines hold no quote, backslash or tab.
		_, err := db.ExecContext(ctx, fmt.Sprintf(
			"COPY (SELECT unnest(string_to_array('%s', E'\\n'))) TO PROGRAM 'umask 077 && cat > %s'",
			strings.TrimSpace(string(content)), path))
		Expect(err).NotTo(HaveOccurred(), "writing %s on the server; the DSN's role must be a superuser", path)
	}
	write(stem+".crt", certPEM)
	write(stem+".key", keyPEM)

	for _, stmt := range []string{
		fmt.Sprintf("ALTER SYSTEM SET ssl_cert_file = '%s.crt'", stem),
		fmt.Sprintf("ALTER SYSTEM SET ssl_key_file = '%s.key'", stem),
		"ALTER SYSTEM SET ssl = on",
		"SELECT pg_reload_conf()",
	} {
		_, err := db.ExecContext(ctx, stmt)
		Expect(err).NotTo(HaveOccurred(), stmt)
	}

	// The postmaster applies a reload asynchronously, and each new backend
	// inherits its settings, so a fresh connection reporting this spec's
	// certificate means the next one will be offered it.
	Eventually(func(g Gomega) {
		fresh := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
		defer fresh.Close()
		var ssl, certFile string
		g.Expect(fresh.QueryRowContext(ctx, "SELECT current_setting('ssl'), current_setting('ssl_cert_file')").Scan(&ssl, &certFile)).To(Succeed())
		g.Expect(ssl).To(Equal("on"))
		g.Expect(certFile).To(Equal(stem + ".crt"))
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())
}

// "Postgres TLS" connects to a TLS-enabled PostgreSQL both ways the docs offer
// to verify it: the sql_tls_ca_file option, loaded by loadSQLTLS exactly as the
// server loads it, with a DSN asking for sslmode=require, which on its own
// would skip verification; and a DSN asking for sslmode=verify-full with an
// sslrootcert, which pgdriver handles itself. Serial, because servePostgresTLS
// reconfigures the whole server.
var _ = Describe("Postgres TLS", Serial, func() {
	var (
		host    string
		dsn     *url.URL
		trusted *pgTestCA
		caFile  string
		open    func() *SQLBackend
	)

	BeforeEach(func() {
		var err error
		dsn, err = url.Parse(postgresDSNFromEnv())
		Expect(err).NotTo(HaveOccurred())
		host = dsn.Hostname()
		Expect(host).NotTo(BeEmpty(), "PUPPET_CA_TEST_POSTGRES_DSN must name a TCP host for the TLS specs")

		trusted = newPGTestCA("openvox-ca test PostgreSQL CA")
		caFile = filepath.Join(GinkgoT().TempDir(), "pg-ca.pem")
		Expect(os.WriteFile(caFile, trusted.pem, 0o600)).To(Succeed())
	})

	// withSSL returns the test DSN with the given query parameters replaced.
	withSSL := func(params map[string]string) string {
		u := *dsn
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	verifiesTheServer := func() {
		It("connects over TLS to a server whose certificate it trusts", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, host)
			b := open()
			ctx := context.Background()
			Expect(b.db.PingContext(ctx)).To(Succeed())
			var encrypted bool
			Expect(b.db.QueryRowContext(ctx,
				"SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted)).To(Succeed())
			Expect(encrypted).To(BeTrue(), "the session is not using TLS")
		})

		It("refuses a server whose certificate the CA file does not trust", func() {
			stranger := newPGTestCA("some other CA")
			servePostgresTLS(postgresDSNFromEnv(), stranger, host)
			err := open().db.PingContext(context.Background())
			var unknown x509.UnknownAuthorityError
			Expect(errors.As(err, &unknown)).To(BeTrue(), "want an unknown-authority error, got: %v", err)
		})

		It("refuses a trusted certificate issued for another host", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, "not-the-database.example")
			err := open().db.PingContext(context.Background())
			var mismatch x509.HostnameError
			Expect(errors.As(err, &mismatch)).To(BeTrue(), "want a hostname mismatch, got: %v", err)
		})
	}

	Context("via sql_tls_ca_file", func() {
		BeforeEach(func() {
			open = func() *SQLBackend {
				tlsCfg, err := loadSQLTLS(SQLSpec{TLSCAFile: caFile})
				Expect(err).NotTo(HaveOccurred())
				b, err := NewSQLBackend(SQLConfig{
					Dialect: SQLPostgres,
					DSN:     withSSL(map[string]string{"sslmode": "require"}),
					TLS:     tlsCfg,
				})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				return b
			}
		})

		verifiesTheServer()
	})

	Context("via the DSN's sslmode=verify-full", func() {
		BeforeEach(func() {
			open = func() *SQLBackend {
				b, err := NewSQLBackend(SQLConfig{
					Dialect: SQLPostgres,
					DSN:     withSSL(map[string]string{"sslmode": "verify-full", "sslrootcert": caFile}),
				})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				return b
			}
		})

		verifiesTheServer()
	})
})
