/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"intel/isecl/lib/common/context"
	"net/http"

	"github.com/gorilla/mux"
)

func SetTestJwt(r *mux.Router) {
	r.Handle("/jwt", getJwtFromToken()).Methods("GET")
}

func getJwtFromToken() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to getJwtFromToken")
		defer defaultLog.Trace("getJwtFromToken return")

		roles, err := context.GetUserRoles(r)
		if err != nil {
			return &resourceError{Message: "not able to get roles from http context", StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(roles)
		if err != nil {
			return &resourceError{Message: "could not encode json structure", StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}
