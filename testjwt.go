package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"intel/isecl/authservice/jwt"
	"net"
	"strings"
	_"time"
)
type Role struct{
	Service string `json:"service,omitempty"`
	Name string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

type CtClaims struct {
	Roles []Role `json:"roles"`
}


func GenerateKeyPair(keyType string, keyLength int) (crypto.PublicKey, error) {
	
	switch(strings.ToLower(keyType)){
	case "rsa":
		if keyLength != 4096{
			keyLength = 3072
		}
		k, err := rsa.GenerateKey(rand.Reader, keyLength)
		if err != nil {
			return nil, fmt.Errorf("could not generate rsa key pair Error: %s", err)
		}
		return k,nil
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
			return nil, fmt.Errorf("could not generate ecdsa key pair Error: %s", err)
		}
		return k, nil
	}

}

func getSignatureAlgorithm(privKey crypto.PrivateKey) (x509.SignatureAlgorithm, error){
	// set the signature algorithm based on privatekey generated.
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return x509.SHA384WithRSA, nil
	case *ecdsa.PrivateKey:
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
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported private key type when generating certificate request. Only rsa and ecdsa supported")	
	}
}

// CreateKeyPairAndCertificateRequest taken in parameters for certificate request and return der bytes for the CSR
// and a PKCS8 private key. We are using PKCS8 since we could can have a single package for ecdsa or rsa keys.
func CreateKeyPairAndCertificateRequest(subject, hostList, keyType string, keyLength int ) (certReq []byte, pkcs8Der []byte, err error){

	//first let us look at type of keypair that we are generating
	privKey, err := GenerateKeyPair(keyType, keyLength)
	if err != nil {
		return nil, nil, err
	}

	//notBefore := time.Now()
	//notAfter := notBefore.Add(8760 * time.Hour) // 1 year
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{subject},
		},
	}
	template.SignatureAlgorithm, err = getSignatureAlgorithm(privKey)
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

	certReq, err = x509.CreateCertificateRequest(rand.Reader, &template,  privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not create certificate request. error : %s", err)
	}
	pkcs8Der, err =  x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
	}
	return certReq, pkcs8Der, nil
}



func (a *App) TestTokenAuth() error {
	fmt.Println("Inside the TestTokenAuth Function")
	keyCurve := elliptic.P384()
	privKey, err := ecdsa.GenerateKey(keyCurve, rand.Reader)
	if err != nil {
		fmt.Println(err)
		return err
	}
	derbytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("Der bytes %s", derbytes)
	
	factory, err := jwtauth.NewTokenFactory(derbytes, "Test Issuer", 0)
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
	fmt.Println("JWT :",jwt)
	return nil

}
