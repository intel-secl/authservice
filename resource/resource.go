/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	consts "intel/isecl/authservice/constants"
	comctx "intel/isecl/lib/common/context"
	"intel/isecl/lib/common/log"

	"intel/isecl/lib/common/auth"
	ct "intel/isecl/lib/common/types/aas"
	"net/http"

	"github.com/jinzhu/gorm"

	commLogMsg "intel/isecl/lib/common/log/message"
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

func AuthorizeEndpoint(r *http.Request, roleNames []string, needContext bool, retNilCtxForEmptyCtx bool) (*map[string]ct.RoleInfo, error) {
	// Check query authority
	privileges, err := comctx.GetUserRoles(r)
	if err != nil {
		secLog.WithError(err).Error(commLogMsg.InvalidInputBadParam)
		return nil,
			&resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
	}

	// this function check if the user requesting to perform operation has the right roles.
	reqRoles := make([]ct.RoleInfo, len(roleNames))
	for i, role := range roleNames {
		reqRoles[i] = ct.RoleInfo{Service: consts.ServiceName, Name: role}
	}

	ctxMap, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges, reqRoles, retNilCtxForEmptyCtx)
	if !foundRole {
		secLog.Infof("%s: endpoint access unauthorized, request roles: %v", commLogMsg.UnauthorizedAccess, roleNames)
		return nil, &privilegeError{Message: "", StatusCode: http.StatusForbidden}
	}

	return ctxMap, nil
}

func AuthorizeEndPointAndGetServiceFilter(r *http.Request, roleNames []string) ([]string, error) {
	ctxMap, err := AuthorizeEndpoint(r, roleNames, true, true)
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
