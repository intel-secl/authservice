package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"intel/isecl/authservice/jwt"
)
type Role struct{
	Domain string `json:"domain"`
	Name string `json:"name"`
	Scope string `json:"scope"`
}

type CtClaims struct {
	Roles Role `json:"roles"`
	Test  int `json:"testfield,omitempty"`
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
	
	factory, err := jwtauth.NewJwtFactory(derbytes, "Test Issuer", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	claims := CtClaims{Roles:Role{"TDS","HostUpdater","HostA"}, Test:1}
	fmt.Println(claims)
	jwt, err := factory.Create(&claims,"Vinil's JWT", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("JWT :",jwt)
	return nil

}
