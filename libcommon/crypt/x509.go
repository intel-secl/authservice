package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	_ "intel/isecl/authservice/constants"
	"math/big"
	"net"
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
		return k, k.PublicKey, nil
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
func CreateKeyPairAndCertificate(subject, hostList, keyType string, keyLength int) (certReq []byte, pkcs8Der []byte, err error) {

	//first let us look at type of keypair that we are generating
	privKey, pubKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
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
	pkcs8Der, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return cert, pkcs8Der, nil
}
