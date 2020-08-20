/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	consts "intel/isecl/authservice/v3/constants"
	"intel/isecl/lib/common/v3/validation"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/gorilla/mux"

	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

func SetJwtCertificate(r *mux.Router) {
	r.Handle("/jwt-certificates", getJwtCertificate()).Methods("GET")
}

func getJwtCertificate() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to getJwtCertificate")
		defer defaultLog.Trace("getJwtCertificate return")

		token_certificate, err := ioutil.ReadFile(consts.TokenSignCertFile)
		if err != nil {
			return err
		}

		re := regexp.MustCompile(`\r?\n`)
		err = validation.ValidatePemEncodedKey(re.ReplaceAllString(string(token_certificate), ""))

		if err != nil {
			secLog.Errorf(commLogMsg.UnauthorizedAccess, err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Invalid jwt certificate"))
			return err
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(token_certificate)
		secLog.Info(commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil

	}
}
