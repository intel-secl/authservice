package main

import (
	"encoding/pem"
	"fmt"
	"intel/isecl/authservice/libcommon/jwt"
	"intel/isecl/authservice/libcommon/crypt"
	"os"
)
type Role struct{
	Service string `json:"service,omitempty"`
	Name string `json:"name"`
	Scope string `json:"scope,omitempty"`
}

type CtClaims struct {
	Roles []Role `json:"roles"`
}



func (a *App) TestTokenAuth() error {
	fmt.Println("Inside the TestTokenAuth Function")

	//certReq, privKeyDer, err := CreateKeyPairAndCertificateRequest("AAS JWT Signing", "", "ecdsa", 0)
	cert, privKeyDer, err := crypt.CreateKeyPairAndCertificate("AAS JWT Signing", "", "ecdsa", 0)
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
	fmt.Printf("\n\n\n Token Generation Complete. Testing Token verification and retrieving claims\n\n\n")
	if err := a.ValidateToken(certPemBytes, jwt); err != nil{
		return err
	}
	fmt.Printf("\n\n Token Validation Complete.\n\n")
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
