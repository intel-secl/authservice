/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	consts "intel/isecl/authservice/v3/constants"
	comctx "intel/isecl/lib/common/v3/context"
	"intel/isecl/lib/common/v3/log"

	"intel/isecl/lib/common/v3/auth"
	ct "intel/isecl/lib/common/v3/types/aas"
	"net/http"

	"github.com/jinzhu/gorm"

	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	defaultLog.Trace("call to query handler")
	defer defaultLog.Trace("query handler return")

	if err := ehf(w, r); err != nil {
		secLog.WithError(err).Warning(commLogMsg.InvalidInputProtocolViolation)
		if gorm.IsRecordNotFoundError(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		switch t := err.(type) {
		case *resourceError:
			defaultLog.WithError(err).Warningf("resource error")
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			defaultLog.WithError(err).Warningf("resource error")
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			defaultLog.WithError(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func AuthorizeEndpoint(r *http.Request, permissionNames []string, retNilCtxForEmptyCtx bool) (*map[string]ct.PermissionInfo, error) {
	// Check query authority
	privileges, err := comctx.GetUserPermissions(r)
	if err != nil {
		secLog.WithError(err).Error(commLogMsg.InvalidInputBadParam)
		return nil,
			&resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
	}
	// this function check if the user requesting to perform operation has the right roles.
	reqPermissions := ct.PermissionInfo{Service: consts.ServiceName, Rules: permissionNames}

	ctxMap, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions, retNilCtxForEmptyCtx)
	if !foundMatchingPermission {
		secLog.Infof("%s: endpoint access unauthorized, request permissions: %v", commLogMsg.UnauthorizedAccess, permissionNames)
		return nil, &privilegeError{Message: "", StatusCode: http.StatusForbidden}
	}

	return ctxMap, nil
}

func AuthorizeEndPointAndGetServiceFilter(r *http.Request, permissionNames []string) ([]string, error) {
	ctxMap, err := AuthorizeEndpoint(r, permissionNames, true)
	if err != nil {
		return nil, err
	}
	svcFltr := []string{}
	if ctxMap != nil {
		for _, val := range *ctxMap {
			svcFltr = append(svcFltr, val.Context)
		}
	}
	return svcFltr, nil
}
