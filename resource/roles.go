/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"errors"
	ct "intel/isecl/authservice/libcommon/types"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	_ "github.com/gorilla/context"
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
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&rl.RoleInfo)
		if err != nil {
			return err
		}
		// validate role
		if rl.Name == "" {
			return errors.New("rolename is invalid")
		}
		/*
			valid_err = validation.ValidateRolename(h.Rolename)
			if valid_err != nil {
				return fmt.Errorf("rolename validation fail: %s", valid_err.Error())
			}
		*/

		// Check query authority
		var privilege *ct.UserRoles
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.UserRoles); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		existingRole, err := db.RoleRepository().Retrieve(types.Role{RoleInfo: types.RoleInfo{Service: rl.Service, Name: rl.Name, Context: rl.Context}})
		if existingRole != nil {
			w.WriteHeader(http.StatusForbidden) // HTTP 403
			return errors.New("same role exists")
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

		id := mux.Vars(r)["id"]
		// Check query authority
		var privilege *ct.UserRoles
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.UserRoles); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		rl, err := db.RoleRepository().Retrieve(types.Role{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve role")
			return err
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
		id := mux.Vars(r)["id"]
		// Check query authority
		var privilege *ct.UserRoles
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.UserRoles); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		del_rl, err := db.RoleRepository().Retrieve(types.Role{ID: id})
		if del_rl == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid role")
			return &resourceError{Message: "failed to delete: double check input role id",
				StatusCode: http.StatusBadRequest}
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
		// Check query authority
		var privilege *ct.UserRoles
		if rv := r.Context().Value("userroles"); rv != nil {
			if rl, ok := rv.(*ct.UserRoles); ok {
				privilege = rl
			}
		}

		// TODO: check for the right roles and change following check
		if privilege == nil {
			log.Error("No roles found in token")
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query roles")
		service := r.URL.Query().Get("service")
		roleName := r.URL.Query().Get("name")
		context := r.URL.Query().Get("context")

		filter := types.Role{
			RoleInfo: types.RoleInfo{
				Service: service,
				Name:    roleName,
				Context: context,
			},
		}

		roles, err := db.RoleRepository().RetrieveAll(filter)
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
