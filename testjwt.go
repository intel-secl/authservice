package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"intel/isecl/authservice/jwt"
	_"intel/isecl/authservice/constants"
	"net"
	"os"
	"strings"
	"math/big"
	"time"
)
type Role struct{
	Service string `json:"service,omitempty"`
	Name string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

type CtClaims struct {
	Roles []Role `json:"roles"`
}


func GenerateKeyPair(keyType string, keyLength int) (crypto.PrivateKey, crypto.PublicKey, error) {
	
	switch(strings.ToLower(keyType)){
	case "rsa":
		if keyLength != 4096{
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

func getSignatureAlgorithm(pubKey crypto.PublicKey) (x509.SignatureAlgorithm, error){
	// set the signature algorithm based on privatekey generated.
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return x509.SHA384WithRSA, nil
	case *ecdsa.PublicKey:
		bitLen := key.Curve.Params().BitSize
		switch bitLen {
		case 384:
			return x509.ECDSAWithSHA384, nil
		case 521,512:
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
func CreateKeyPairAndCertificateRequest(subject, hostList, keyType string, keyLength int ) (certReq []byte, pkcs8Der []byte, err error){

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

	certReq, err = x509.CreateCertificateRequest(rand.Reader, &template,  pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate request. error : %s", err)
	}
	pkcs8Der, err =  x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return certReq, pkcs8Der, nil
}


// CreateKeyPairAndCertificateRequest taken in parameters for certificate request and return der bytes for the CSR
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificate(subject, hostList, keyType string, keyLength int ) (certReq []byte, pkcs8Der []byte, err error){

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
	pkcs8Der, err =  x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return cert, pkcs8Der, nil
}


func (a *App) TestTokenAuth() error {
	fmt.Println("Inside the TestTokenAuth Function")

	//certReq, privKeyDer, err := CreateKeyPairAndCertificateRequest("AAS JWT Signing", "", "ecdsa", 0)
	cert, privKeyDer, err := CreateKeyPairAndCertificate("AAS JWT Signing", "", "ecdsa", 0)
	if err != nil {
		return err
	}
	
	//todo - after testing funnctionality writing to file, uncomment section as we have to create file in a particular dir
	/*
	err = os.MkdirAll(constants.TokenSignKeysAndCertDir, os.ModeDir)
	if err != nil {
		return err
	}
	// marshal private key to disk
	keyOut, err := os.OpenFile(constants.TokenSignKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return fmt.Errorf("tls setup: %v", err)
	}
	// private key should not be world readable
	os.Chmod(constants.TokenSignKeyFile, 0640)
	defer keyOut.Close()
	*/
	 
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}
	
	//if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certReq}); err != nil {
	//	return fmt.Errorf("could not pem encode certificate request: %v", err)
	//}

	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return fmt.Errorf("could not pem encode certificate request: %v", err)
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

	factory, err := jwtauth.NewTokenFactory(privKeyDer, true, certPemBytes, "AAS JWT Signing", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	roles := []Role {Role{"CMS","CertificateRequester","CN:aas.isecl.intel.com"}, Role{"TDS","HostUpdater","HostA"}, Role{"WLS","Administrator",""}}
	claims := CtClaims{roles}
	fmt.Println(claims)
	jwt, err := factory.Create(&claims,"Vinil's JWT", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("\nJWT :",jwt)
	fmt.Println("\n\n\n Token Generation Complete. Testing Token verification and retrieving claims\n\n\n")
	if err := a.ValidateToken(certPemBytes, jwt); err != nil{
		return err
	}
	fmt.Println("\n\n Token Validation Complete.\n\n")
	return nil

}


func (a *App) ValidateToken(certPem []byte, jwtString string) error {
	v, err := jwtauth.NewVerifier(certPem)
	if err != nil {
		return err
	}
	claims := CtClaims{}
	v.ValidateTokenAndGetClaims(jwtString, &claims)
	if err != nil {
		return err
	}
	fmt.Println(claims)

	return nil
}
