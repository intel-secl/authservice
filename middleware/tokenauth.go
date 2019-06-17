/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"intel/isecl/authservice/libcommon/jwt"
	cos "intel/isecl/authservice/libcommon/os"
	ct "intel/isecl/authservice/libcommon/types"

	_"intel/isecl/authservice/context"
	"intel/isecl/authservice/constants"
	_"intel/isecl/authservice/repository"
	_"intel/isecl/authservice/types"

	_ "github.com/gorilla/context"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"strings"
)

var jwtVerifier jwtauth.Verifier

func initJwtVerifier() (err error){
	
	certPems, err := cos.GetDirFileContents(constants.TrustedJWTSigningCertsDir, "*.pem" )
	if err != nil {
		return err
	}

	jwtVerifier, err = jwtauth.NewVerifier(certPems)
	if err != nil {
		return err
	}
	return nil

}

type httpContextKey string

//var userRoleKey = httpContextKey("userroles")

func SetUserRoles(r *http.Request, val *ct.UserRoles) *http.Request {

	ctx := context.WithValue(r.Context(), "userroles", val)
	return r.WithContext(ctx)
}

func GetUserRoles(r *http.Request) *ct.UserRoles {
	if rv := r.Context().Value("userroles"); rv != nil {
		return rv.(*ct.UserRoles)
	}
	return nil
}

func retrieveAndSaveTrustedJwtSigningCerts(){
	// todo. this function will make https requests and save files
	// to the directory where we keep trusted certificates
}

func NewTokenAuth() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// lets start by making sure jwt token verifier is initalized

		if jwtVerifier == nil {
			if err := initJwtVerifier(); err != nil {
				log.WithError(err).Error("not able to initialize jwt verifier.")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// pull up the bearer token.

		splitAuthHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
		if len(splitAuthHeader) <= 1 {
			log.Error("no bearer token provided for authorization")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// the second item in the slice should be the jwtToken. let try to validate
		claims := ct.UserRoles{}
		_, err := jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(splitAuthHeader[1]), &claims)
		if err != nil {
			// lets check if the failure is because we could not find a public key used to sign the token
			// We will be able to check this only if there is a kid (key id) field in the JWT header.
			// check the details of the jwt library implmentation to see how this is done
			if noCertErr, ok := err.(*jwtauth.MatchingCertNotFoundError); ok {
				//fmt.Println(noCertErr)
				fmt.Println("Matching Certificate hash not found. Try to pull down and save the certificate now", noCertErr)
				// let us try to load tokens from list of URLs with JWT signing certificates that we trust
				
				retrieveAndSaveTrustedJwtSigningCerts()
				// hopefully, we now have the necesary certificate files in the appropriate directory
				// re-initialize the verifier to pick up any new certificate. 
				
				// TODO: There is a danger in doing this. Someone could keep sending token with some random kid value to 
				// get this module to retrieve certificates over https connection slowing down the web server. 
				// Its kind of a DDOS. We should be able to fix this by making the
				// above function to return an error for too may attempts of some kind of flag indicating that all the certs
				// have been pulled. 
				if err := initJwtVerifier(); err != nil {
					log.WithError(err).Error("not able to initialize jwt verifier.")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				
			}
			// this is a validation failure. Let us log the message and return unauthorized
			log.WithError(err).Error("token validation Failure")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r = SetUserRoles(r, &claims)
		next.ServeHTTP(w, r)
		})
	}
}