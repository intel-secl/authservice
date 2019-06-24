/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package context

import (
	"context"
	"fmt"
	"net/http"

	"intel/isecl/authservice/libcommon/types"
)

type httpContextKey string

var userRoleKey = httpContextKey("userroles")

func SetUserRoles(r *http.Request, val []types.RoleInfo) *http.Request {

	ctx := context.WithValue(r.Context(), "userroles", val)
	return r.WithContext(ctx)
}

/*
 func SetUserRoles(r *http.Request, val types.Roles) *http.Request {

	 ctx := context.WithValue(r.Context(), userRoleKey, val)
	 return r.WithContext(ctx)
 }
*/
func GetUserRoles(r *http.Request) ([]types.RoleInfo, error) {
	if rv := r.Context().Value("userroles"); rv != nil {
		if ur, ok := rv.([]types.RoleInfo); ok {
			return ur, nil
		}
	}
	return nil, fmt.Errorf("could not retrieve user roles from context")
}
