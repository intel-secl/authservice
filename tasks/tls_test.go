/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"intel/isecl/lib/common/setup"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTlsCertCreation(t *testing.T) {
	assert := assert.New(t)
	keyData, certData, err := createSelfSignedCert([]string{"10.0.0.1", "intel.com"})
	assert.NoError(err)
	key, err := x509.ParsePKCS1PrivateKey(keyData)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.Equal(cert.IPAddresses[0], net.ParseIP("10.0.0.1").To4())
	assert.Contains(cert.DNSNames, "intel.com")
	assert.True(cert.IsCA)
	assert.NoError(cert.VerifyHostname("intel.com"))
	assert.Equal(cert.PublicKey, &key.PublicKey)
}

func TestOutboundHost(t *testing.T) {
	host, err := outboundHost()
	assert.NoError(t, err)
	assert.NotNil(t, host)
}

func TestTlsSetup(t *testing.T) {
	cert, _ := ioutil.TempFile("", "cert")
	key, _ := ioutil.TempFile("", "key")
	// remove now, so we can stat later
	os.Remove(cert.Name())
	os.Remove(key.Name())
	s := TLS{
		Flags:         nil,
		TLSCertFile:   cert.Name(),
		TLSKeyFile:    key.Name(),
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NoError(t, err)
	assert.FileExists(t, cert.Name())
	assert.FileExists(t, key.Name())
}

func TestValidate(t *testing.T) {
	cert, _ := ioutil.TempFile("", "cert")
	key, _ := ioutil.TempFile("", "key")
	s := TLS{
		Flags:         nil,
		TLSCertFile:   cert.Name(),
		TLSKeyFile:    key.Name(),
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NoError(t, err)
}
