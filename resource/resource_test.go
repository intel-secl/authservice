/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	"github.com/gorilla/mux"
)

var user_role types.Role

func setupRouter(db repository.AASDatabase, user_role types.Role) *mux.Router {
	m := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = context.SetUserRoles(r, []types.Role{user_role})
			next.ServeHTTP(w, r)
		})
	}
	r := mux.NewRouter().PathPrefix("/aas").Subrouter()
	r.Use(m)
	SetHosts(r, db)
	return r
}
