/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	consts "intel/isecl/authservice/constants"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

func SetRoles(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/roles", handlers.ContentTypeHandler(createRole(db), "application/json")).Methods("POST")
	r.Handle("/roles", queryRoles(db)).Methods("GET")
	r.Handle("/roles/{id}", deleteRole(db)).Methods("DELETE")
	r.Handle("/roles/{id}", getRole(db)).Methods("GET")
	r.Handle("/roles/{id}", handlers.ContentTypeHandler(updateRole(db), "application/json")).Methods("PATCH")
}

func createRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var rl types.Role

		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
			return err
		}

		// we have the role now. If ctxMap is not nil, we need to make sure that the right privilege is
		// available to create a role with the requested service
		if ctxMap != nil {
			if _, ok := (*ctxMap)[rl.Service]; !ok {
				log.Errorf("restricted role - not allowed to create role is service : %s", rl.Service)
				return &privilegeError{Message: "", StatusCode: http.StatusForbidden}
			}
		}

		// at this point, we should have privilege to create the requested role. So, lets proceed

		if (r.ContentLength == 0) {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&rl.RoleInfo)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
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

		existingRole, err := db.RoleRepository().Retrieve(types.Role{RoleInfo: ct.RoleInfo{Service: rl.Service, Name: rl.Name, Context: rl.Context}})
		if existingRole != nil {
			return &resourceError{Message: "same role exists", StatusCode: http.StatusBadRequest}
		}

		created, err := db.RoleRepository().Create(rl)
		if err != nil {
			return err
		}

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

		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
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
		rl, err := db.RoleRepository().Retrieve(types.Role{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve role")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
		// a role in the token that can read this role
		if ctxMap != nil {
			if _, ok := (*ctxMap)[rl.Service]; !ok {
				log.Errorf("restricted role - cannot allow role read roles in service : %s", rl.Service)
				return &privilegeError{Message: "", StatusCode: http.StatusForbidden}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(rl)
		if err != nil {
			log.WithError(err).Error("failed to encode json response")
			return err
		}
		return nil
	}
}

func deleteRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		// authorize rest api endpoint based on token
		ctxMap, err := AuthorizeEndpoint(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName}, true, true)
		if err != nil {
			return err
		}
		
		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		del_rl, err := db.RoleRepository().Retrieve(types.Role{ID: id})
		if del_rl == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid role")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
		// a role in the token that can read this role
		if ctxMap != nil {
			if _, ok := (*ctxMap)[del_rl.Service]; !ok {
				log.Errorf("restricted role - cannot allow deleting roles in service : %s", del_rl.Service)
				return &privilegeError{Message: "", StatusCode: http.StatusForbidden}
			}
		}

		if err := db.RoleRepository().Delete(*del_rl); err != nil {
			log.WithError(err).WithField("id", id).Info("failed to delete role")
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func queryRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		var validation_err error

		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.RoleManagerGroupName, consts.RoleAndUserManagerGroupName})
		if err != nil {
			return err
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query roles")
		service := r.URL.Query().Get("service")
		roleName := r.URL.Query().Get("name")
		context := r.URL.Query().Get("context")

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

		filter := types.Role{
			RoleInfo: ct.RoleInfo{
				Service: service,
				Name:    roleName,
				Context: context,
			},
		}

		fmt.Println("Service filter", svcFltr)
		roles, err := db.RoleRepository().RetrieveAll(filter, []string{}, svcFltr)
		if err != nil {
			log.WithError(err).WithField("filter", filter).Info("failed to retrieve roles")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(roles)
		return nil
	}
}

func updateRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		return &resourceError{Message: "", StatusCode: http.StatusNotImplemented}
	}
}
