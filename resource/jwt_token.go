/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/crypt"
	jwtauth "intel/isecl/lib/common/jwt"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"
	"io/ioutil"
	"time"

	authcommon "intel/isecl/authservice/common"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	"github.com/gorilla/mux"
)

var tokFactory *jwtauth.JwtFactory

type roleClaims struct {
	Roles        types.Roles         `json:"roles"`
	Permisssions []ct.PermissionInfo `json:"permissions,omitempty",`
}

//  declared in resource.go
//  var defaultLog = log.GetDefaultLogger()
//  var secLog = log.GetSecurityLogger()

func SetJwtToken(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/token", createJwtToken(db)).Methods("POST")
}

func initJwtTokenFactory() error {

	defaultLog.Trace("call to initJwtTokenFactory")
	defer defaultLog.Trace("initJwtTokenFactory return")

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

	tokFactory, err = jwtauth.NewTokenFactory(privKeyDer,
		cfg.Token.IncludeKid, certPemBytes,
		"AAS JWT Issuer",
		time.Duration(cfg.Token.TokenDurationMins)*time.Minute)
	return err
}

func createJwtToken(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to createJwtToken")
		defer defaultLog.Trace("createJwtToken return")

		//check if the token factory is already initialized. If not, initialize the token factory
		if tokFactory == nil {
			err := initJwtTokenFactory()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				defaultLog.WithError(err).Errorf("could not initialize the token factory. error - %v", err)
				return nil
			}
		}

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		var uc ct.UserCred
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&uc)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err := validation.ValidateUserNameString(uc.UserName)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusUnauthorized}
		}

		validation_err = validation.ValidatePasswordString(uc.Password)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusUnauthorized}
		}

		u := db.UserRepository()

		if httpStatus, err := authcommon.HttpHandleUserAuth(u, uc.UserName, uc.Password); err != nil {
			secLog.Warningf("User [%s] auth failed, requested from %s: ", uc.UserName, r.RemoteAddr)
			return &resourceError{Message: "", StatusCode: httpStatus}
		}

		roles, err := u.GetRoles(types.User{Name: uc.UserName}, nil, false)
		if err != nil {
			return &resourceError{Message: "Database error: unable to retrive roles", StatusCode: http.StatusInternalServerError}
		}
		perms, err := u.GetPermissions(types.User{Name: uc.UserName}, nil)
		if err != nil {
			return &resourceError{Message: "Database error:", StatusCode: http.StatusInternalServerError}
		}

		//ur := []ct.RoleInfo {ct.RoleInfo{"CMS","CertificateRequester","CN:aas.isecl.intel.com"}, ct.RoleInfo{"TDS","HostUpdater","HostA"}, ct.RoleInfo{"WLS","Administrator",""}}
		//claims := roleClaims{Roles: roles.Role}

		jwt, err := tokFactory.Create(&roleClaims{Roles: roles, Permisssions: perms}, uc.UserName, 0)
		if err != nil {
			return &resourceError{Message: "could not generate token", StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwt))
		secLog.Infof("Return JWT token of user [%s] to: %s", uc.UserName, r.RemoteAddr)
		return nil
	}

}
