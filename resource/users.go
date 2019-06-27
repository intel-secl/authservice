/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"errors"
	"intel/isecl/authservice/libcommon/context"
	ct "intel/isecl/authservice/libcommon/types"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	_ "github.com/gorilla/context"
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

		var uc types.UserCreate
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&uc)
		if err != nil {
			return err
		}
		// validate user
		if uc.Name == "" {
			return errors.New("username is invalid")
		}
		/*
			 valid_err = validation.ValidateUsername(h.Username)
			 if valid_err != nil {
				 return fmt.Errorf("username validation fail: %s", valid_err.Error())
			 }
		*/

		// Check query authority
		var privilege *ct.RoleSlice
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.RoleSlice); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		existingUser, err := db.UserRepository().Retrieve(types.User{Name: uc.Name})
		if existingUser != nil {
			return &resourceError{Message: "same user exists", StatusCode: http.StatusForbidden}
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

		id := mux.Vars(r)["id"]
		// Check query authority
		var privilege *ct.RoleSlice
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.RoleSlice); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			return err
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
		id := mux.Vars(r)["id"]
		// Check query authority
		var privilege *ct.RoleSlice
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.RoleSlice); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		del_usr, err := db.UserRepository().Retrieve(types.User{ID: id})
		if del_usr == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid user")
			return &resourceError{Message: "failed to delete: double check input user id",
				StatusCode: http.StatusBadRequest}
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
		// Check query authority
		var privilege *ct.RoleSlice
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.RoleSlice); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query users")
		userName := r.URL.Query().Get("name")

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

		id := mux.Vars(r)["id"]

		//todo: validate id in uuid format

		var rids types.RoleIDs
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&rids)
		if err != nil {
			return err
		}

		// todo: validate string list of UUIDs

		// validation.ValidateUUIDslice(rids.RoleUUIDs)

		roles, err := context.GetUserRoles(r)
		if err != nil {
			log.WithError(err).Error("could not get user roles from http context")
			return &resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
		}

		// TODO: check for the right roles before proceeding - remove following line
		log.Errorf("not checking user authorization - roles available %v", roles)

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			return err
		}

		err = db.UserRepository().AddRoles(*u, rids, true)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		w.WriteHeader(http.StatusCreated) // HTTP 201
		return nil
	}
}

func queryUserRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		id := mux.Vars(r)["id"]
		var roleFilter *types.Role
		//todo: validate id and role_id in uuid format

		// get the roles from request context
		roles, err := context.GetUserRoles(r)
		if err != nil {
			log.WithError(err).Error("could not get user roles from http context")
			return &resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
		}

		// TODO: check for the right roles before proceeding - remove following line
		log.Errorf("not checking user authorization - roles available %v", roles)

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query users")
		roleName := r.URL.Query().Get("name")
		service := r.URL.Query().Get("service")
		context := r.URL.Query().Get("context")

		if roleName != "" || service != "" || context != "" {
			roleFilter = &types.Role{RoleInfo: ct.RoleInfo{Service: service, Name: roleName, Context: context}}
		}

		userRoles, err := db.UserRepository().GetRoles(types.User{ID: id}, roleFilter, true)
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

		id := mux.Vars(r)["id"]
		rid := mux.Vars(r)["role_id"]

		//todo: validate id and role_id in uuid format

		// get the roles from request context
		roles, err := context.GetUserRoles(r)
		if err != nil {
			log.WithError(err).Error("could not get user roles from http context")
			return &resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
		}

		// TODO: check for the right roles before proceeding - remove following line
		log.Errorf("not checking user authorization - roles available %v", roles)

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			return err
		}

		err = db.UserRepository().DeleteRole(*u, rid)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		w.WriteHeader(http.StatusNoContent) // HTTP 204
		return nil
	}
}