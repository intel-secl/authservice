/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	consts "intel/isecl/authservice/constants"
	"io/ioutil"
	"net/http"
	"intel/isecl/lib/common/validation"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"regexp"
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

		re := regexp.MustCompile(`\r?\n`)
		err = validation.ValidatePemEncodedKey(re.ReplaceAllString(string(token_certificate), ""))

		if err != nil{
			log.Errorf("Invalid jwt certificate in file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Invalid jwt certificate"))
			return err
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(token_certificate)
		return nil

	}
}
