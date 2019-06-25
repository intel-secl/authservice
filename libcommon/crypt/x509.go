package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	_ "intel/isecl/authservice/constants"
	"intel/isecl/lib/common/crypt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func GenerateKeyPair(keyType string, keyLength int) (crypto.PrivateKey, crypto.PublicKey, error) {

	switch strings.ToLower(keyType) {
	case "rsa":
		if keyLength != 4096 {
			keyLength = 3072
		}
		k, err := rsa.GenerateKey(rand.Reader, keyLength)
		if err != nil {
			return nil, nil, fmt.Errorf("could not generate rsa key pair Error: %s", err)
		}
		return k, &k.PublicKey, nil
	// if the keytype is not "rsa", then we will always use ecdsa as this is the preferred
	//
	default:
		keyCurve := elliptic.P384()
		// below is not the correct check. we should check if the keylength == 521. But people might
		// be intending 512 for a stronger elliptical curve or 4096 which is meant for RSA.
		// so we will just check for keyLength >= 512
		if keyLength >= 512 {
			keyCurve = elliptic.P521()
		}
		k, err := ecdsa.GenerateKey(keyCurve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("could not generate ecdsa key pair Error: %s", err)
		}
		return k, &k.PublicKey, nil
	}

}

func getSignatureAlgorithm(pubKey crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	// set the signature algorithm based on privatekey generated.
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return x509.SHA384WithRSA, nil
	case *ecdsa.PublicKey:
		bitLen := key.Curve.Params().BitSize
		switch bitLen {
		case 384:
			return x509.ECDSAWithSHA384, nil
		case 521, 512:
			return x509.ECDSAWithSHA512, nil
			// we should not really get into the 256 case as long as Generate keypair only support ecdsa keylength of 384 or 512.
			// just in case
		case 256:
			return x509.ECDSAWithSHA256, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("upsupported signature algorithm for certificate with ecdsa keys. only sha 384, 512 supported")

		}
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported public key type when generating certificate request. Only rsa and ecdsa supported")
	}
}

// CreateKeyPairAndCertificateRequest taken in parameters for certificate request and return der bytes for the CSR
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificateRequest(subject, hostList, keyType string, keyLength int) (certReq []byte, pkcs8Der []byte, err error) {

	//first let us look at type of keypair that we are generating
	privKey, pubKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{subject},
		},
	}
	template.SignatureAlgorithm, err = getSignatureAlgorithm(pubKey)
	if err != nil {
		return nil, nil, err
	}

	hosts := strings.Split(hostList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certReq, err = x509.CreateCertificateRequest(rand.Reader, &template, pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate request. error : %s", err)
	}
	pkcs8Der, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return certReq, pkcs8Der, nil
}

// CreateKeyPairAndCertificateRequest taken in parameters for certificate request and return der bytes for the CSR
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificate(subject, hostList, keyType string, keyLength int) ([]byte, []byte, error) {

	//first let us look at type of keypair that we are generating
	privKey, pubKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
	}

	// generate self signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(8760 * time.Hour) // 1 year
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subject},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	template.SignatureAlgorithm, err = getSignatureAlgorithm(pubKey)
	if err != nil {
		return nil, nil, err
	}

	hosts := strings.Split(hostList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate. error : %s", err)
	}
	pkcs8Der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return cert, pkcs8Der, nil
}

// GetPublicKeyFromCertPem retrieve the public key from a certificate pem block
// We only support ECDSA and RSA public key
func GetPublicKeyFromCertPem(certPem []byte) (crypto.PublicKey, error) {
	cert, err := GetCertFromPem(certPem)
	if err != nil {
		return "", err
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as RSA cert does not match RSA public key struct")
	case x509.ECDSA:
		if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key algorithm of cert reported as ECDSA cert does not match ECDSA public key struct")
	}
	return nil, fmt.Errorf("only RSA and ECDSA public keys are supported")
}

func GetCertFromPem(certPem []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

// GetCertHashFromPemInHex returns hash of a certificate from a Pem block
func GetCertHashFromPemInHex(certPem []byte, hashAlg crypto.Hash) (string, error) {
	cert, err := GetCertFromPem(certPem)
	if err != nil {
		return "", err
	}
	hash, err := crypt.GetHashData(cert.Raw, hashAlg)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash), nil
}

func SavePrivateKeyAsPKCS8(keyDer []byte, filePath string) error {

	// marshal private key to disk
	keyOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	// private key should not be world readable
	os.Chmod(filePath, 0640)
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: keyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}
	return nil

}

func GetPKCS8PrivKeyDerFromFile(filePath string) ([]byte, error) {

	privKeyPem, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read from private key file %s : ", filePath)
	}

	block, _ := pem.Decode(privKeyPem)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private Key PEM file")
	}

	return block.Bytes, nil
}

func SavePemCertWithShortSha1FileName(certPem []byte, dir string) error {
	sha1Hex, err := GetCertHashFromPemInHex(certPem, crypto.SHA1)
	if err != nil {
		return err
	}
	// open file with restricted permissions
	filePath := filepath.Join(dir, sha1Hex[:9]+".pem")
	certOut, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("could not open private key file for writing: %v", err)
	}
	// private key should not be world readable
	os.Chmod(filePath, 0640)
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certPem}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}

	return nil
}
