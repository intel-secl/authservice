/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	consts "intel/isecl/authservice/constants"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

func SetJwtCertificate(r *mux.Router) {
	r.Handle("/jwt-certificates", getJwtCertificate()).Methods("GET")
}

func getJwtCertificate() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		token_certificate, err := ioutil.ReadFile(consts.TokenSignCertFile)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(token_certificate)
		return nil

	}
}
