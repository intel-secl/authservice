/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	consts "intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"
	"net/http"
	"strconv"

	"github.com/gorilla/handlers"

	"github.com/gorilla/mux"
)

//  declared in resource.go
//  var defaultLog = log.GetDefaultLogger()
//  var secLog = log.GetSecurityLogger()

func SetRoles(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/roles", handlers.ContentTypeHandler(createRole(db), "application/json")).Methods("POST")
	r.Handle("/roles", queryRoles(db)).Methods("GET")
	r.Handle("/roles/{id}", deleteRole(db)).Methods("DELETE")
	r.Handle("/roles/{id}", getRole(db)).Methods("GET")
	r.Handle("/roles/{id}", handlers.ContentTypeHandler(updateRole(db), "application/json")).Methods("PATCH")
}

func createRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to createRole")
		defer defaultLog.Trace("createRole return")

		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
			return err
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		rl := types.Role{}
		err = dec.Decode(&rl.RoleInfo)
		if err != nil {
			secLog.Warning("Unauthorized create role attempt from:", r.RemoteAddr)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		// we have the role now. If ctxMap is not nil, we need to make sure that the right privilege is
		// available to create a role with the requested service
		if ctxMap != nil {
			if _, ok := (*ctxMap)[rl.Service]; !ok {
				errMsg := fmt.Sprintf("restricted role - not allowed to create role as service: %s", rl.Service)
				secLog.Error(errMsg)
				return &privilegeError{Message: errMsg, StatusCode: http.StatusForbidden}
			}
		}

		// at this point, we should have privilege to create the requested role. So, lets proceed

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		validation_err := ValidateRoleString(rl.Name)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err = ValidateServiceString(rl.Service)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err = ValidateContextString(rl.Context)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		// at this point, we should have privilege to create the requested role. So, lets proceed

		existingRole, err := db.RoleRepository().Retrieve(&types.RoleSearch{
			RoleInfo:    ct.RoleInfo{Service: rl.Service, Name: rl.Name, Context: rl.Context},
			AllContexts: false,
		})

		if existingRole != nil {
			secLog.WithField("role", rl).Warning("Trying to create duplicated role from addr:", r.RemoteAddr)
			return &resourceError{Message: "same role exists", StatusCode: http.StatusBadRequest}
		}

		created, err := db.RoleRepository().Create(rl)
		if err != nil {
			return err
		}
		secLog.WithField("role", rl).Info("Role created by:", r.RemoteAddr)

		w.WriteHeader(http.StatusCreated) // HTTP 201
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(created)
		if err != nil {
			return err
		}
		return nil
	}
}

func getRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to getRole")
		defer defaultLog.Trace("getRole return")

		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
			secLog.Warning("Unauthorized get role attempt from:", r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		// at this point, we should get the role and later check if user has permission to read this role.
		// this is not as efficient. It retrieves a record from the database even though the user does
		// not have privilege to read the record.
		rl, err := db.RoleRepository().Retrieve(&types.RoleSearch{AllContexts: true, IDFilter: []string{id}})

		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve role")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
		// a role in the token that can read this role
		if ctxMap != nil {
			if _, ok := (*ctxMap)[rl.Service]; !ok {
				errMsg := fmt.Sprintf("restricted role - cannot allow role read roles in service: %s", rl.Service)
				secLog.Error(errMsg)
				return &privilegeError{Message: errMsg, StatusCode: http.StatusForbidden}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(rl)
		if err != nil {
			// log.WithError(err).Error("failed to encode json response")
			return err
		}
		secLog.WithField("role", rl).Info("Return get role request to:", r.RemoteAddr)
		return nil
	}
}

func deleteRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to deleteRole")
		defer defaultLog.Trace("deleteRole return")

		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
			secLog.Warning("Unauthorized delete role attempt from:", r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		del_rl, err := db.RoleRepository().Retrieve(&types.RoleSearch{AllContexts: true, IDFilter: []string{id}})
		if del_rl == nil || err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("attempt to delete invalid role")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
		// a role in the token that can read this role
		if ctxMap != nil {
			if _, ok := (*ctxMap)[del_rl.Service]; !ok {
				errMsg := fmt.Sprintf("restricted role - cannot allow deleting roles in service: %s", del_rl.Service)
				secLog.Warning(errMsg)
				return &privilegeError{Message: errMsg, StatusCode: http.StatusForbidden}
			}
		}

		if err := db.RoleRepository().Delete(*del_rl); err != nil {
			// log.WithError(err).WithField("id", id).Info("failed to delete role")
			return err
		}
		secLog.WithField("role", del_rl).Info("Role deleted by:", r.RemoteAddr)

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func queryRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to queryRoles")
		defer defaultLog.Trace("queryRoles return")

		var validation_err error

		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName})
		if err != nil {
			secLog.Warning("Unauthorized query role attempt from:", r.RemoteAddr)
			return err
		}

		// check for query parameters
		defaultLog.WithField("query", r.URL.Query()).Trace("query roles")
		service := r.URL.Query().Get("service")
		roleName := r.URL.Query().Get("name")
		context := r.URL.Query().Get("context")
		contextContains := r.URL.Query().Get("contextContains")
		queryAllContexts := r.URL.Query().Get("allContexts")

		if len(roleName) != 0 {
			if validation_err := ValidateRoleString(roleName); validation_err != nil {
				return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		if len(service) > 0 {
			if validation_err = ValidateServiceString(service); validation_err != nil {
				return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		if len(context) > 0 {
			if validation_err = ValidateContextString(context); validation_err != nil {
				return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		if len(contextContains) > 0 {
			if validation_err = ValidateContextString(contextContains); validation_err != nil {
				return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		// set allContexts to true - override if we get a valid entry from query parameter
		allContexts := true
		if getAllContexts, err := strconv.ParseBool(queryAllContexts); err == nil {
			allContexts = getAllContexts
		}

		filter := types.RoleSearch{
			RoleInfo: ct.RoleInfo{
				Service: service,
				Name:    roleName,
				Context: context,
			},
			ContextContains: contextContains,
			ServiceFilter:   svcFltr,
			AllContexts:     allContexts,
		}

		roles, err := db.RoleRepository().RetrieveAll(&filter)
		if err != nil {
			// log.WithError(err).WithField("filter", filter).Info("failed to retrieve roles")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(roles)
		secLog.Info("Return role query to:", r.RemoteAddr)
		return nil
	}
}

func updateRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		return &resourceError{Message: "", StatusCode: http.StatusNotImplemented}
	}
}
