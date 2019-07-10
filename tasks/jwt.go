package tasks

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
	"io"
	"os"
	"strings"
)

type JWT struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (jwt JWT) Run(c setup.Context) error {

	// no cms - should remove
	// 1. call CreateKeyPairAndCertificate
	// 2. save private key with pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}) to TokenSignKeyFile
	// 3. pem encode cert and save to TokenSignCertFile
	// 4. save to TrustedJWTSigningCertsDir with SavePemCertWithShortSha1FileName
	fmt.Fprintln(jwt.ConsoleWriter, "Running jwt setup...")

	envJwtCertSub, _ := c.GetenvString("AAS_JWT_CERT_SUBJECT", "AAS JWT Certificate Subject")
	envJwtIncludeKid, _ := c.GetenvString("AAS_JWT_INCLUDE_KEYID", "AAS include key id in JWT Token")
	envJwtTokenDurationMins, _ := c.GetenvInt("AAS_JWT_TOKEN_DURATION_MINS", "AAS JWT Token duration in mins")

	//set up the defaults
	if envJwtCertSub == "" {
		envJwtCertSub = "AAS JWT Signing Certificate"
	}

	jwt.Config.Token.IncludeKid = true
	if strings.ToLower(envJwtIncludeKid) == "false" {
		jwt.Config.Token.IncludeKid = false
	}

	fs := flag.NewFlagSet("jwt", flag.ContinueOnError)
	fs.StringVar(&envJwtCertSub, "subj", envJwtCertSub, "JWT Signing Certificate Subject")
	fs.IntVar(&jwt.Config.Token.TokenDurationMins, "valid-mins", envJwtTokenDurationMins, "JWT Token validation minutes")
	fs.BoolVar(&jwt.Config.Token.IncludeKid, "keyid", jwt.Config.Token.IncludeKid, "JWT include Key ID")
	err := fs.Parse(jwt.Flags)
	if err != nil {
		return err
	}

	cert, privKeyDer, err := crypt.CreateKeyPairAndCertificate(envJwtCertSub, "", "", 0)
	if err != nil {
		return err
	}

	keyOut, err := os.OpenFile(constants.TokenSignKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	os.Chmod(constants.TokenSignKeyFile, 0640)
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}

	certOut, err := os.OpenFile(constants.TokenSignCertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	os.Chmod(constants.TokenSignCertFile, 0640)
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}

	certBuf := new(bytes.Buffer)
	err = pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err = crypt.SavePemCertWithShortSha1FileName(certBuf.Bytes(), constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return err
	}

	//set the configuration
	// with cms
	// 1. call CreateKeyPairAndCertificateRequest, get cert from cms
	// 2. save private key with pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}) to TokenSignKeyFile
	// 3. write cert to TokenSignCertFile
	// 4. save to TrustedJWTSigningCertsDir with SavePemCertWithShortSha1FileName

	return jwt.Config.Save()
}

func (jwt JWT) Validate(c setup.Context) error {

	return nil
}
