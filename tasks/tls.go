/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Should move this to lib common, as it is duplicated across several projects

type TLS struct {
	Flags         []string
	TLSKeyFile    string
	TLSCertFile   string
	ConsoleWriter io.Writer
	// config  Config
}

func outboundHost() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return os.Hostname()
	}
	defer conn.Close()

	return (conn.LocalAddr().(*net.UDPAddr)).IP.String(), nil
}

func createSelfSignedCert(hosts []string) (key []byte, cert []byte, err error) {
	reader := rand.Reader
	k, err := rsa.GenerateKey(reader, 4096)
	if err != nil {
		return
	}
	key = x509.MarshalPKCS1PrivateKey(k)
	if err != nil {
		return
	}

	// generate self signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(8760 * time.Hour) // 1 year
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ISecL Self Signed"},
		},
		SignatureAlgorithm:    x509.SHA384WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// parse hosts
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	cert, err = x509.CreateCertificate(rand.Reader, &template, &template, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	return
}

func (ts TLS) Run(c setup.Context) error {
	fmt.Fprintln(ts.ConsoleWriter, "Running tls setup...")
	fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing tls keys")
	defaultHostname, err := c.GetenvString("AAS_TLS_HOST_NAMES", "comma separated list of hostnames to add to TLS self signed cert")
	if err != nil {
		defaultHostname, _ = outboundHost()
	}
	host := fs.String("host_names", defaultHostname, "comma separated list of hostnames to add to TLS self signed cert")

	err = fs.Parse(ts.Flags)
	if err != nil {
		return err
	}
	if *force || ts.Validate(c) != nil {
		if *host == "" {
			return errors.New("tls setup: no hostnames specified")
		}
		hosts := strings.Split(*host, ",")

		// validate host names
		for _, h := range hosts {
			valid_err := validation.ValidateHostname(h)
			if valid_err != nil {
				return valid_err
			}
		}
		key, cert, err := createSelfSignedCert(hosts)
		if err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
		// marshal private key to disk
		keyOut, err := os.OpenFile(ts.TLSKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
		if err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
		// private key should not be world readable
		os.Chmod(ts.TLSKeyFile, 0640)
		defer keyOut.Close()
		if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: key}); err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
		// marshal cert to disk
		certOut, err := os.OpenFile(ts.TLSCertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
		if err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
		os.Chmod(ts.TLSCertFile, 0644)
		defer certOut.Close()
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
	} else {
		fmt.Println("TLS already configured, skipping")
	}
	return nil
}

func (ts TLS) Validate(c setup.Context) error {
	_, err := os.Stat(ts.TLSCertFile)
	if os.IsNotExist(err) {
		return errors.New("TLSCertFile is not configured")
	}
	_, err = os.Stat(ts.TLSKeyFile)
	if os.IsNotExist(err) {
		return errors.New("TLSKeyFile is not configured")
	}
	return nil
}
