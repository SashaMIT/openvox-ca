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

package storage

import (
	"crypto/tls"
	"crypto/x509"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/uptrace/bun/driver/pgdriver"
)

var _ = Describe("PostgreSQL sql_tls_* configuration", func() {
	var base *tls.Config

	BeforeEach(func() {
		// pgdriver falls back to PGHOST and PGPORT for a DSN that names no
		// host; empty them so the runner's environment cannot move the answer.
		GinkgoT().Setenv("PGHOST", "")
		GinkgoT().Setenv("PGPORT", "")
		// Every field loadBackendTLS can set, so a refactor that rebuilds the
		// config rather than cloning it cannot drop one unnoticed.
		base = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      x509.NewCertPool(),
			Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}},
		}
	})

	// configFor parses dsn exactly as openSQLDB does.
	configFor := func(dsn string) *pgdriver.Config {
		return pgdriver.NewConnector(pgdriver.WithDSN(dsn)).Config()
	}

	DescribeTable("verifies the server against the host the driver dials",
		func(dsn, want string) {
			conf := configFor(dsn)
			Expect(applyPostgresTLS(conf, base)).To(Succeed())
			Expect(conf.TLSConfig.ServerName).To(Equal(want))
			Expect(conf.TLSConfig.InsecureSkipVerify).To(BeFalse())
			Expect(conf.TLSConfig.RootCAs).To(BeIdenticalTo(base.RootCAs))
			Expect(conf.TLSConfig.Certificates).To(Equal(base.Certificates))
			Expect(conf.TLSConfig.MinVersion).To(Equal(base.MinVersion))
		},
		Entry("a hostname", "postgres://u:p@db.example.com:5432/ca", "db.example.com"),
		Entry("a hostname on the default port", "postgres://u:p@db.example.com/ca", "db.example.com"),
		Entry("an IPv4 address", "postgres://u:p@192.0.2.10:5432/ca", "192.0.2.10"),
		Entry("an IPv6 address", "postgres://u:p@[2001:db8::10]:5432/ca", "2001:db8::10"),
		Entry("no host, so the driver's localhost default", "postgres://u:p@/ca", "localhost"),
		// pgdriver applies host= after the URL's host, so host= is what it
		// dials, and so what must be verified.
		Entry("a TCP host= overriding the URL's host", "postgres://u:p@decoy.example.com:5432/ca?host=real.example.com:5432", "real.example.com"),
		// sslmode=require on its own means "encrypt, do not verify", and
		// pgdriver builds an InsecureSkipVerify config for it. The files must
		// replace that rather than inherit it.
		Entry("a DSN asking for sslmode=require", "postgres://u:p@db.example.com:5432/ca?sslmode=require", "db.example.com"),
		// The files are the request for TLS, so sslmode=disable does not
		// switch it off; this has always been their precedence.
		Entry("a DSN asking for sslmode=disable", "postgres://u:p@db.example.com:5432/ca?sslmode=disable", "db.example.com"),
	)

	It("follows PGHOST when the DSN names no host, as the driver does", func() {
		GinkgoT().Setenv("PGHOST", "pg.example.net")
		conf := configFor("postgres://u:p@/ca")
		Expect(applyPostgresTLS(conf, base)).To(Succeed())
		Expect(conf.TLSConfig.ServerName).To(Equal("pg.example.net"))
	})

	It("leaves the loaded configuration untouched for its next user", func() {
		Expect(applyPostgresTLS(configFor("postgres://u:p@db.example.com/ca"), base)).To(Succeed())
		Expect(base.ServerName).To(BeEmpty())
	})

	DescribeTable("refuses a DSN with no single host to verify",
		func(dsn, reason string) {
			Expect(applyPostgresTLS(configFor(dsn), base)).To(MatchError(ContainSubstring(reason)))
		},
		Entry("a Unix socket named by host=", "postgres://u:p@/ca?host=/var/run/postgresql", "unix socket"),
		Entry("a unix:// DSN", "unix://u:p@ca/var/run/postgresql/.s.PGSQL.5432", "unix socket"),
		Entry("several hosts", "postgres://u:p@db1.example.com:5432,db2.example.com:5432/ca", "names several"),
		Entry("several hosts on the default port", "postgres://u:p@db1.example.com,db2.example.com/ca", "names several"),
		Entry("a port with no host", "postgres://u:p@:5432/ca", "cannot find the PostgreSQL host"),
		// pgdriver appends the default port only to a host with no colon in
		// it, so a bracketed IPv6 address without one reaches it portless.
		Entry("an IPv6 address with no port", "postgres://u:p@[2001:db8::10]/ca", "cannot find the PostgreSQL host"),
	)

	// The refusal belongs to the sql_tls_* files alone: without them the same
	// DSNs open exactly as before. NewSQLBackend connects lazily, so neither
	// half dials anything.
	DescribeTable("refuses at open time only when sql_tls_* is set",
		func(dsn, reason string) {
			_, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: dsn, TLS: base})
			Expect(err).To(MatchError(ContainSubstring(reason)))

			b, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			Expect(b.Close()).To(Succeed())
		},
		Entry("a Unix socket", "postgres://u:p@/ca?host=/var/run/postgresql", "unix socket"),
		Entry("several hosts", "postgres://u:p@db1.example.com:5432,db2.example.com:5432/ca", "names several"),
	)
})
