/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	authcommon "intel/isecl/authservice/v3/common"
	"intel/isecl/authservice/v3/context"
	_ "intel/isecl/authservice/v3/defender"
	"intel/isecl/authservice/v3/repository"
	"intel/isecl/authservice/v3/types"
	"net/http"
	_ "time"

	"github.com/gorilla/mux"

	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

var defaultLogger = commLog.GetDefaultLogger()
var secLogger = commLog.GetSecurityLogger()

func NewBasicAuth(u repository.UserRepository) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			defaultLogger.Trace("entering NewBasicAuth")
			defer defaultLogger.Trace("leaving NewBasicAuth")

			// TODO : switch to username only
			username, password, ok := r.BasicAuth()

			if !ok {
				defaultLogger.Info("No Basic Auth provided")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if httpStatus, err := authcommon.HttpHandleUserAuth(u, username, password); err != nil {
				secLogger.Warning(commLogMsg.UnauthorizedAccess, err.Error())
				w.WriteHeader(httpStatus)
				return
			}
			secLogger.Info(commLogMsg.AuthorizedAccess, username)

			roles, err := u.GetRoles(types.User{Name: username}, nil, false)
			if err != nil {
				defaultLogger.WithError(err).Error("Database error: unable to retrive roles")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			r = context.SetUserRoles(r, roles)
			next.ServeHTTP(w, r)
		})
	}
}
