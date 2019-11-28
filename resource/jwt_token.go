/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	jwtauth "intel/isecl/lib/common/jwt"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"

	authcommon "intel/isecl/authservice/common"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	"github.com/gorilla/mux"

	commLogMsg "intel/isecl/lib/common/log/message"
)

type roleClaims struct {
	Roles        types.Roles         `json:"roles"`
	Permisssions []ct.PermissionInfo `json:"permissions,omitempty",`
}

//  declared in resource.go
//  var defaultLog = log.GetDefaultLogger()
//  var secLog = log.GetSecurityLogger()

func SetJwtToken(r *mux.Router, db repository.AASDatabase, tokFactory *jwtauth.JwtFactory) {
	r.Handle("/token", createJwtToken(db, tokFactory)).Methods("POST")
}

func createJwtToken(db repository.AASDatabase, tokFactory *jwtauth.JwtFactory) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to createJwtToken")
		defer defaultLog.Trace("createJwtToken return")

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
			secLog.Warningf("%s: User [%s] auth failed, requested from %s: ", commLogMsg.AuthenticationFailed, uc.UserName, r.RemoteAddr)
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
		secLog.Infof("%s: Return JWT token of user [%s] to: %s", commLogMsg.TokenIssued, uc.UserName, r.RemoteAddr)
		return nil
	}

}
