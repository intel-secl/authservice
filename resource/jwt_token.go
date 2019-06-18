/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
	ct "intel/isecl/authservice/libcommon/types"
	"intel/isecl/authservice/libcommon/crypt"
	"intel/isecl/authservice/libcommon/jwt"

	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/constants"
	"intel/isecl/authservice/config"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

var tokFactory *jwtauth.JwtFactory 
func SetJwtToken(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/token", createJwtToken(db)).Methods("POST")
}


func initJwtTokenFactory() error{
	
	// retrieve the private key from file
	privKeyDer, err := crypt.GetPKCS8PrivKeyDerFromFile(constants.TokenSignKeyFile)
	if err != nil {
		return fmt.Errorf("Could not get private key - error : %v", err)
	}

	// retrieve the signing key certificate used to create the file
	cfg := config.Global()
	var certPemBytes []byte
	if cfg.Token.IncludeKid {
		certPemBytes, err = ioutil.ReadFile(constants.TokenSignCertFile)
		if err != nil {
			return fmt.Errorf("could not read JWT signing certificate file - error : %v", err)
		}
	}

	tokFactory, err =  jwtauth.NewTokenFactory(privKeyDer, 
									cfg.Token.IncludeKid, certPemBytes,
									"AAS JWT Issuer",
									time.Duration(cfg.Token.TokenDurationMins) * time.Minute)
	return err;
}

func createJwtToken(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		//check if the token factory is already initialized. If not, initialize the token factory
		if tokFactory == nil {
			err := initJwtTokenFactory()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.WithError(err).Errorf("could not initialize the token factory. error - %v", err)
				return nil
			}
		}

		var uc ct.UserCred
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&uc)
		if err != nil {
			return err
		}

		//TODO: validate the username and password. Since this is not in place, we are going to skip and generate a sample token
		ur := []ct.UserRole {ct.UserRole{"CMS","CertificateRequester","CN:aas.isecl.intel.com"}, ct.UserRole{"TDS","HostUpdater","HostA"}, ct.UserRole{"WLS","Administrator",""}}
		claims := ct.UserRoles{ur}

		jwt, err := tokFactory.Create(&claims, uc.UserName, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.WithError(err).Errorf("could not generate token")
			return nil
		}
		

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwt))
		return nil
	}

}
