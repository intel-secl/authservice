/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/authservice/constants"
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/version"
	"net/http"

	"github.com/gorilla/mux"
)

func SetVersion(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == constants.AdminGroupName {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			http.Error(w, "version query not allowed", http.StatusForbidden)
			return
		}

		verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
		w.Write([]byte(verStr))
	})
}
