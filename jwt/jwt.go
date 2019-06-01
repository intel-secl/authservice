/* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package jwtauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const defaultTokenValidity time.Duration = 24 * time.Hour

type JwtFactory struct {
	privKey       crypto.PrivateKey
	issuer        string
	tokenValidity time.Duration
	signingMethod jwt.SigningMethod
}

func getJwtSigningMethod(privKey crypto.PrivateKey) (jwt.SigningMethod, error) {

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		bitLen := key.N.BitLen()
		if bitLen != 3072 && bitLen != 4096 {
			return nil, fmt.Errorf("RSA keylength for JWT signing must be 3072 or 4096")
		}
		return jwt.GetSigningMethod("HS384"), nil
	case *ecdsa.PrivateKey:
		bitLen := key.Curve.Params().BitSize
		if bitLen != 256 && bitLen != 384 {
			return nil, fmt.Errorf("RSA keylength for JWT signing must be 256 or 384")
		}
		if bitLen == 384 {
			return jwt.GetSigningMethod("ES384"), nil
		}
		return jwt.GetSigningMethod("ES256"), nil
	default:
		return nil, fmt.Errorf("unsupported key type for JWT signing. only RSA and ECDSA supported")
	}

}

// NewJwtFactory method allows to create a factory object that can be used to generate the token.
// basically, it allows to load the private key just once and keep using it. The issuer and default
// validity can be passed in so that these do not have to be passed in every time.
func NewJwtFactory(pkcs8der []byte, issuer string, tokenValidity time.Duration) (*JwtFactory, error) {
	if tokenValidity == 0 {
		tokenValidity = defaultTokenValidity
	}

	key, err := x509.ParsePKCS8PrivateKey(pkcs8der)
	if err != nil {
		return nil, err
	}
	signingMethod, err := getJwtSigningMethod(key)
	if err != nil {
		return nil, err
	}
	return &JwtFactory{privKey: key,
		issuer:        issuer,
		tokenValidity: tokenValidity,
		signingMethod: signingMethod,
	}, nil
}

type StandardClaims jwt.StandardClaims

type jwtClaims struct {
	jwt.StandardClaims
	clientClaims interface{}
}

// We are doing custom marshalling here to combine the standard attributes of a JWT and the claims
// that we want to add. Everything would be at the top level. For instance, if we want to carry
//
func (c jwtClaims) MarshalJSON() ([]byte, error) {

	slice1, err := json.Marshal(c.clientClaims)
	if err != nil {
		return nil, err
	}
	slice2, err := json.Marshal(c.StandardClaims)
	if err != nil {
		return nil, err
	}
	slice1[len(slice1)-1] = ','
	slice2[0] = ' '
	fmt.Printf("Claims Json: %s", append(slice1, slice2...))
	return append(slice1, slice2...), nil
}

// Create generates a token based on the claims structure passed in. We collapse the claims with the standard
// jwt claims. Each client need only worry about what he would like to include in the claims.
// Of course the token is signed as well.
func (f *JwtFactory) Create(claims interface{}, subject string, validity time.Duration) (string, error) {
	if validity == 0 {
		validity = f.tokenValidity
	}
	now := time.Now()

	jwtclaim := jwtClaims{}
	jwtclaim.StandardClaims.IssuedAt = now.Unix()
	jwtclaim.StandardClaims.ExpiresAt = now.Add(validity).Unix()
	jwtclaim.StandardClaims.Issuer = f.issuer
	jwtclaim.StandardClaims.Subject = subject

	jwtclaim.clientClaims = claims
	/*
		slice1, err := json.Marshal(claims)
		if err != nil {
			return "", err
		}
		fmt.Printf("client calims : %s\n", slice1)
		slice2, err := json.Marshal(jwtclaim.StandardClaims)
		if err != nil {
			return "", err
		}
		fmt.Printf("standard calims : %s\n", slice2)
		slice1[len(slice1)-1] = ','
		slice2[0] = ' '
		fmt.Printf("Merged JSON :%s", append(slice1, slice2...))
	*/
	token := jwt.NewWithClaims(f.signingMethod, jwtclaim)
	return token.SignedString(f.privKey)

}
