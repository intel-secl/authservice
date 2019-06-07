/* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package jwtauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"intel/isecl/lib/common/crypt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const defaultTokenValidity time.Duration = 24 * time.Hour

type JwtFactory struct {
	privKey       crypto.PrivateKey
	issuer        string
	tokenValidity time.Duration
	signingMethod jwt.SigningMethod
	keyId         string
}

type StandardClaims jwt.StandardClaims
type CustomClaims interface{}

type claims struct {
	jwt.StandardClaims
	customClaims interface{}
}

type Token struct {
	jwtToken       *jwt.Token
	standardClaims *jwt.StandardClaims
	customClaims   interface{}
}

func (t *Token) GetClaims() interface{} {
	return t.customClaims
}

func (t *Token) GetAllClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.jwtToken.Claims
}

func (t *Token) GetStandardClaims() interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return t.standardClaims
}

func (t *Token) GetHeader() *map[string]interface{} {
	if t.jwtToken == nil {
		return nil
	}
	return &t.jwtToken.Header
}

type verifierPrivate struct {
	pubKey     crypto.PublicKey
	pubKeyMap  map[string]crypto.PublicKey
	publicName string
}
type Verifier interface {
	ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error)
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

// NewTokenFactory method allows to create a factory object that can be used to generate the token.
// basically, it allows to load the private key just once and keep using it. The issuer and default
// validity can be passed in so that these do not have to be passed in every time.
func NewTokenFactory(pkcs8der []byte, includeKeyIdInToken bool, signingCertPem []byte, issuer string, tokenValidity time.Duration) (*JwtFactory, error) {
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

	var keyId string

	//todo - we need to decide if we should use the information in the cert
	if includeKeyIdInToken && len(signingCertPem) > 0 {
		block, _ := pem.Decode(signingCertPem)
		if block == nil {
			return nil, fmt.Errorf("NewTokenFactory: failed to parse signing certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("NewTokenFactory: failed to parse certificate: " + err.Error())
		}
		hash, _ := crypt.GetHashData(cert.Raw, crypto.SHA1)
		keyId = hex.EncodeToString(hash)

	}

	return &JwtFactory{privKey: key,
		issuer:        issuer,
		tokenValidity: tokenValidity,
		signingMethod: signingMethod,
		keyId:         keyId,
	}, nil
}

// We are doing custom marshalling here to combine the standard attributes of a JWT and the claims
// that we want to add. Everything would be at the top level. For instance, if we want to carry
//
func (c claims) MarshalJSON() ([]byte, error) {

	slice1, err := json.Marshal(c.customClaims)
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
func (f *JwtFactory) Create(clms interface{}, subject string, validity time.Duration) (string, error) {
	if validity == 0 {
		validity = f.tokenValidity
	}
	now := time.Now()

	jwtclaim := claims{}
	jwtclaim.StandardClaims.IssuedAt = now.Unix()
	jwtclaim.StandardClaims.ExpiresAt = now.Add(validity).Unix()
	jwtclaim.StandardClaims.Issuer = f.issuer
	jwtclaim.StandardClaims.Subject = subject

	jwtclaim.customClaims = clms
	token := jwt.NewWithClaims(f.signingMethod, jwtclaim)
	if f.keyId != "" {
		token.Header["kid"] = f.keyId
	}
	return token.SignedString(f.privKey)

}

//TODO: move to common crypto

// GetPublicKeyFromCertPem retrieve the public key from a certificate pem block
// We only support ECDSA and RSA public key
func GetPublicKeyFromCertPem(certPem []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: " + err.Error())
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

// GetCertHashFromPemInHex returns hash of a certificate from a Pem block
func GetCertHashFromPemInHex(certPem []byte, hashAlg crypto.Hash) (string, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	hash, err := crypt.GetHashData(cert.Raw, crypto.SHA1)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash), nil
}

//TODO - implement this to parse the claims
func (v *verifierPrivate) ValidateTokenAndGetClaims(tokenString string, customClaims interface{}) (*Token, error) {

	token := Token{}
	token.standardClaims = &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, token.standardClaims, func(token *jwt.Token) (interface{}, error) {
		fmt.Println("Called from within the ParseWithClaims publicKey Name :", v.publicName)
		// if v.pubKey exists, it means that there is only a single public key. We should not even be checking for
		// if there is a kid (key id) in the header
		if v.pubKey != nil {
			fmt.Println("found the public key used to sign the jwt")
			return v.pubKey, nil
		}

		keyIDValue, keyIDExists := token.Header["kid"]
		if keyIDExists {
			fmt.Println("Token Header Key id Value :", keyIDValue)
			var matchPubKey crypto.PublicKey
			var matchPubKeyExists bool
			if keyIDString, ok := keyIDValue.(string); ok {
				matchPubKey, matchPubKeyExists = v.pubKeyMap[keyIDString]
			} else {
				fmt.Println("kid (key id) in jwt header is not a string : %v\n", keyIDValue)
				return nil, fmt.Errorf("kid (key id) in jwt header is not a string : %v", keyIDValue)
			}
			fmt.Println("About to check if matching Pub key exists")
			if matchPubKeyExists {
				fmt.Println("Found a matching public key in the map")
				return matchPubKey, nil
			} else {
				fmt.Printf("could not find certificate with hash that matched kid in token :%s\n", keyIDValue)
				return nil, fmt.Errorf("could not find certificate with hash that matched kid in token :%s", keyIDValue)
			}
		}
		fmt.Printf("public key not found in verifier. we should not have not got here.. something really strange")
		return nil, fmt.Errorf("public key not found in verifier. we should not have not got here.. something really strange")

	})
	if err != nil {
		return nil, err
	}
	token.jwtToken = parsedToken
	// so far we have only got the standardClaims parsed. We need to now fill the customClaims

	parts := strings.Split(tokenString, ".")
	// no need check for the number of segments since the previous ParseWithClaims has already done this check.
	// therefor the following is redundant. If we change the implementation, will need to revisit
	//if len(parts) != 3 {
	//	return nil, "jwt token to be parsed seems to be in "
	//}

	// parse Claims
	var claimBytes []byte

	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return nil, fmt.Errorf("could not decode claims part of the jwt token")
	}
	fmt.Printf("Claim bytes %s\n", claimBytes)
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	err = dec.Decode(customClaims)
	token.customClaims = customClaims

	return &token, nil
}

func NewVerifier(signingCertPems interface{}) (Verifier, error) {

	var certPemSlice [][]byte

	switch signingCertPems.(type) {
	default:
		return nil, fmt.Errorf("signingCertPems has to be of type []byte or [][]byte")
	case [][]byte:
		certPemSlice = signingCertPems.([][]byte)
	case []byte:
		certPemSlice = [][]byte{signingCertPems.([]byte)}

	}
	pubKeyMap := make(map[string]crypto.PublicKey)
	for _, certPem := range certPemSlice {
		// TODO - we should validate the certificate here as well
		// we might just want to take the certificate from the pem here itself
		// then retrieve the public key, hash and also do the verification right
		// here. Otherwise we are parsing the certificate multiple times.

		certHash, err := GetCertHashFromPemInHex(certPem, crypto.SHA1)
		if err != nil {
			continue
		}
		pubKey, err := GetPublicKeyFromCertPem(certPem)
		if err != nil {
			continue
		}
		pubKeyMap[certHash] = pubKey
	}

	verifier := verifierPrivate{}
	switch length := len(pubKeyMap); {
	case length == 0:
		return nil, fmt.Errorf("Could not parse/validate any of the jwt signing certificates ")
	case length == 1:
		for _, pubKeyValue := range pubKeyMap {
			verifier.pubKey = pubKeyValue
		}
	case length > 50:
		return nil, fmt.Errorf("too many jwt signing certificates. Possibly an incorrect directory passed in - unable to continue ")

	case length > 1:
		verifier.pubKeyMap = pubKeyMap
	}

	return &verifier, nil

}
