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
var jwtCertDownloadAttempted bool

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

func retrieveAndSaveTrustedJwtSigningCerts() error{
	if jwtCertDownloadAttempted  {
		return fmt.Errorf("already attempted to download JWT signing certificates. Will not attempt again")
	}
	// todo. this function will make https requests and save files
	// to the directory where we keep trusted certificates

	jwtCertDownloadAttempted = true
	return nil
}

func NewTokenAuth() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// lets start by making sure jwt token verifier is initalized

		// there is a case when the jwtVerifier is not loaded with the right certificates. 
		// In this case, we need to reattempt. So lets run this in a loop
		if jwtVerifier == nil  {
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

		// TODO: Not really liking the 4 level of nested if below.. this works.. but would really
		// like to refactor this to flatten the nested if. This is a problem with golang where the
		// convention is to return an error object. You need to explicitly check the value of the
		// error object and the move onto the next check. 
		
		// the second item in the slice should be the jwtToken. let try to validate
		claims := ct.UserRoles{}
		_, err := jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(splitAuthHeader[1]), &claims)
		if err != nil {
			// lets check if the failure is because we could not find a public key used to sign the token
			// We will be able to check this only if there is a kid (key id) field in the JWT header.
			// check the details of the jwt library implmentation to see how this is done
			if _, ok := err.(*jwtauth.MatchingCertNotFoundError); ok {
				
				// let us try to load certs from list of URLs with JWT signing certificates that we trust
				if err = retrieveAndSaveTrustedJwtSigningCerts(); err == nil {

					// hopefully, we now have the necesary certificate files in the appropriate directory
					// re-initialize the verifier to pick up any new certificate.
					if err = initJwtVerifier(); err != nil {
						log.WithError(err).Error("attempt to reinitialize jwt verifier failed")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					_, err = jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(splitAuthHeader[1]), &claims)

				}
				
			}
		}

		if err != nil {
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