/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	consts "intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"
	"net/http"
	"strconv"

	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
)

func SetUsers(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/users", handlers.ContentTypeHandler(createUser(db), "application/json")).Methods("POST")
	r.Handle("/users", queryUsers(db)).Methods("GET")
	r.Handle("/users/{id}", deleteUser(db)).Methods("DELETE")
	r.Handle("/users/{id}", getUser(db)).Methods("GET")
	r.Handle("/users/{id}", handlers.ContentTypeHandler(updateUser(db), "application/json")).Methods("PATCH")
	r.Handle("/users/{id}/roles", handlers.ContentTypeHandler(addUserRoles(db), "application/json")).Methods("POST")
	r.Handle("/users/{id}/roles", queryUserRoles(db)).Methods("GET")
	r.Handle("/users/{id}/roles/{role_id}", handlers.ContentTypeHandler(deleteUserRole(db), "application/json")).Methods("DELETE")
}

func createUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var uc ct.UserCreate

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserManagerGroupName, consts.RoleAndUserManagerGroupName}, false, true)
		if err != nil {
			return err
		}
		
		if (r.ContentLength == 0) {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&uc)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		// validate user fields
		validation_err := validation.ValidateUserNameString(uc.Name)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err = validation.ValidatePasswordString(uc.Password)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		existingUser, err := db.UserRepository().Retrieve(types.User{Name: uc.Name})
		if existingUser != nil {
			return &resourceError{Message: "same user exists", StatusCode: http.StatusBadRequest}
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(uc.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		created, err := db.UserRepository().Create(types.User{Name: uc.Name, PasswordHash: passwordHash, PasswordCost: bcrypt.DefaultCost})
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

func getUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserManagerGroupName, consts.RoleAndUserManagerGroupName}, false, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(u)
		if err != nil {
			log.WithError(err).Error("failed to encode json response")
			return err
		}
		return nil
	}
}

func deleteUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserManagerGroupName, consts.RoleAndUserManagerGroupName}, false, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		del_usr, err := db.UserRepository().Retrieve(types.User{ID: id})
		if del_usr == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		if err := db.UserRepository().Delete(*del_usr); err != nil {
			log.WithError(err).WithField("id", id).Info("failed to delete user")
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func queryUsers(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserManagerGroupName, consts.RoleAndUserManagerGroupName}, false, true)
		if err != nil {
			return err
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query users")
		userName := r.URL.Query().Get("name")

		if len(userName) != 0 {
			if validation_err := validation.ValidateUserNameString(userName); validation_err != nil {
				return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.User{
			Name: userName,
		}

		users, err := db.UserRepository().RetrieveAll(filter)
		if err != nil {
			log.WithError(err).WithField("filter", filter).Info("failed to retrieve users")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
		return nil
	}
}

func updateUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		return &resourceError{Message: "", StatusCode: http.StatusNotImplemented}
	}
}

func addUserRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleManagerGroupName, consts.RoleAndUserManagerGroupName})
		if err != nil {
			return err
		}
		
		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		var rids ct.RoleIDs
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&rids)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if len(rids.RoleUUIDs) == 0 {
			return &resourceError{Message: "At least one role id is required", StatusCode: http.StatusBadRequest}
		}

		for _, rid := range rids.RoleUUIDs {
			validation_err = validation.ValidateUUIDv4(rid)
			if validation_err != nil {
				return &resourceError{Message: "One or more role ids is not a valid uuid", StatusCode: http.StatusBadRequest}
			}
		}

		// we need to retrieve roles to add by their ids. So we pass in empty filter for role
		// We restrict roles by the privilege use the filter by id
		roles, err := db.RoleRepository().RetrieveAll(&types.RoleSearch{
			IDFilter:      rids.RoleUUIDs,
			ServiceFilter: svcFltr,
			AllContexts:   true,
		})

		if err != nil {
			log.WithError(err).Info("failed to retrieve roles")
			return &resourceError{Message: "One or more role ids does not exist", StatusCode: http.StatusBadRequest}
		}

		// if the number of roles returned from the db does not match the number
		// provided in json, then abort the association(s)
		if len(roles) != len(rids.RoleUUIDs) {
			log.Errorf("could not find matching role or user does not have authorization - requested roles - %s", rids.RoleUUIDs)
			return &resourceError{Message: "One or more role ids does not exist", StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			return &resourceError{Message: "The user id does not exist", StatusCode: http.StatusBadRequest}
		}

		err = db.UserRepository().AddRoles(*u, roles, true)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		w.WriteHeader(http.StatusCreated) // HTTP 201
		return nil
	}
}

func queryUserRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleManagerGroupName, consts.RoleAndUserManagerGroupName})
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query users")
		roleName := r.URL.Query().Get("name")
		service := r.URL.Query().Get("service")
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

		roleSearchFilter := &types.RoleSearch{
			RoleInfo:        ct.RoleInfo{Service: service, Name: roleName, Context: context},
			ContextContains: contextContains,
			AllContexts:     allContexts,
			ServiceFilter:   svcFltr,
		}

		userRoles, err := db.UserRepository().GetRoles(types.User{ID: id}, roleSearchFilter, true)
		if err != nil {
			log.WithError(err).Error("failed to retrieve user roles")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userRoles)
		return nil
	}
}

func deleteUserRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleManagerGroupName, consts.RoleAndUserManagerGroupName})
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		rid := mux.Vars(r)["role_id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err = validation.ValidateUUIDv4(rid)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		err = db.UserRepository().DeleteRole(*u, rid, svcFltr)
		if err != nil {
			log.WithError(err).WithField("id", id).WithField("rid", rid).Info("failed to delete role from user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		w.WriteHeader(http.StatusNoContent) // HTTP 204
		return nil
	}
}
