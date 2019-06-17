/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	ct "intel/isecl/authservice/libcommon/types"
	"net/http"

	"github.com/gorilla/mux"
)

func SetTestJwt(r *mux.Router) {
	r.Handle("/jwt", getJwtFromToken()).Methods("GET")
}

func getJwtFromToken() errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var roles *ct.UserRoles
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.UserRoles); ok {
				roles = rl
			}
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(roles)
		if err != nil {
			return err
		}
		return nil

		/*
			verStr := fmt.Sprintf("%s-%s, auth: %s", version.Version, version.GitHash, r.Header.Get("Authorization"))
			w.Write([]byte(verStr))
			splitToken := strings.Split(r.Header.Get("Authorization"), "Bearer")
			if len(splitToken) > 1 {
				w.Write([]byte(splitToken[1]))
			}
		*/
	}
}
