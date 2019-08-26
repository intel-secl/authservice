/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	authcommon "intel/isecl/authservice/common"
	"intel/isecl/authservice/context"
	_ "intel/isecl/authservice/defender"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"
	_ "time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func NewBasicAuth(u repository.UserRepository) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO : switch to username only
			username, password, ok := r.BasicAuth()

			if !ok {
				log.Info("No Basic Auth provided")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			//todo:remove this entry that is used for debug
			log.Trace("Attempting to authenticate user: ", username)

			if httpStatus, err := authcommon.HttpHandleUserAuth(u, username, password); err != nil {
				log.Error(err)
				w.WriteHeader(httpStatus)
				return
			}

			roles, err := u.GetRoles(types.User{Name: username}, nil, false)
			if err != nil {
				log.WithError(err).Error("Database error: unable to retrive roles")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			r = context.SetUserRoles(r, roles)
			next.ServeHTTP(w, r)
		})
	}
}
