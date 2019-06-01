/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/validation"
	consts "intel/isecl/authservice/constants"
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"net/http"

	_ "github.com/gorilla/context"
	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func SetHosts(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/hosts", handlers.ContentTypeHandler(createHost(db), "application/json")).Methods("POST")
	r.Handle("/hosts", queryHosts(db)).Methods("GET")
	r.Handle("/hosts/{id}", deleteHost(db)).Methods("DELETE")
	r.Handle("/hosts/{id}", getHost(db)).Methods("GET")
	r.Handle("/host", getHost(db)).Methods("GET")
	r.Handle("/hosts/{id}", handlers.ContentTypeHandler(updateHost(db), "application/json")).Methods("PATCH")
}

func createHost(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var h types.Host
		var valid_err error
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&h.HostInfo)
		if err != nil {
			return err
		}
		// validate host
		if h.Hostname == "" {
			return errors.New("hostname is invalid")
		}
		valid_err = validation.ValidateHostname(h.Hostname)
		if valid_err != nil {
			return fmt.Errorf("hostname validation fail: %s", valid_err.Error())
		}

		if h.HardwareUUID == "" {
			return errors.New("hardware uuid is invalid")
		}
		// validate hardware uuid
		valid_err = validation.ValidateHardwareUUID(h.HardwareUUID)
		if valid_err != nil {
			return fmt.Errorf("hardware uuid validation fail: %s", valid_err.Error())
		}

		// Check query authority
		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == consts.AdminGroupName || role.Name == consts.RegisterHostGroupName {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &privilegeError{Message: "privilege error: create host",
				StatusCode: http.StatusForbidden}
		}

		// validate os
		if h.OS != "linux" && h.OS != "windows" {
			return errors.New("os is invalid")
		}
		// validate version
		if h.Version == "" || len(h.Version) > 32 {
			return errors.New("version is invalid")
		}

		if h.Build == "" || len(h.Build) > 32 {
			return errors.New("build is invalid")
		}

		// add the host, it is online after creation,
		// future status will be filled out as queried
		h.Status = "This information is not valid in DB"

		existingHost, err := db.HostRepository().Retrieve(types.Host{HostInfo: types.HostInfo{Hostname: h.Hostname}})

		if existingHost != nil {
			return errors.New("host could not be created")
		}

		created, err := db.HostRepository().Create(h)
		if err != nil {
			return err
		}
		// create the user and roles that represents the new domain. API endpoints that are restricted to updates only from the newly created
		// hosts shall be protected with the role.
		rand, err := crypt.GetRandomBytes(consts.PasswordRandomLength)
		if err != nil {
			return err
		}

		randStr := base64.StdEncoding.EncodeToString(rand)
		hash, err := bcrypt.GenerateFromPassword([]byte(randStr), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		uuid, err := repository.UUID()
		if err != nil {
			return err
		}
		host_user_role := types.Role{ID: uuid, Name: consts.HostSelfUpdateGroupName,
			Domain: created.ID}
		host_user := types.User{Name: created.ID, PasswordHash: hash,
			Roles: []types.Role{host_user_role}}

		user, err := db.UserRepository().Create(host_user)
		if err != nil {
			return err
		}
		resp := types.HostCreateResponse{}
		resp.Host = *created
		resp.User = user.ID
		resp.Token = randStr

		w.WriteHeader(http.StatusCreated) // HTTP 201
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(&resp)
		if err != nil {
			return err
		}
		return nil
	}
}

func getHost(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		id := mux.Vars(r)["id"]
		// Check query authority
		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == consts.AdminGroupName {
				actionAllowed = true
				break
			}
			if role.Name == consts.HostSelfUpdateGroupName && role.Domain == id {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &privilegeError{Message: "privilege error: get host",
				StatusCode: http.StatusForbidden}
		}

		h, err := db.HostRepository().Retrieve(types.Host{ID: id})
		if err != nil {
			log.WithError(err).WithField("id", id).Info("failed to retrieve host")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(&h)
		if err != nil {
			log.WithError(err).Error("failed to encode json response")
			return err
		}
		return nil
	}
}

func deleteHost(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		id := mux.Vars(r)["id"]

		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == consts.AdminGroupName {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &privilegeError{Message: "privilege error: delete host",
				StatusCode: http.StatusForbidden}
		}
		del_h, err := db.HostRepository().Retrieve(types.Host{ID: id})
		if del_h == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid host")
			return &resourceError{Message: "failed to delete: double check input host id",
				StatusCode: http.StatusBadRequest}
		}
		err = deleteHostUserRole(db, del_h)
		if err != nil {
			return err
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func queryHosts(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		roles := context.GetUserRoles(r)
		actionAllowed := false
		for _, role := range roles {
			if role.Name == consts.AdminGroupName {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			return &privilegeError{Message: "privilege error: query hosts",
				StatusCode: http.StatusForbidden}
		}

		// check for query parameters
		log.WithField("query", r.URL.Query()).Trace("query hosts")
		hostname := r.URL.Query().Get("hostname")
		hardwareUUID := r.URL.Query().Get("hardwareUUID")
		version := r.URL.Query().Get("version")
		build := r.URL.Query().Get("build")
		os := r.URL.Query().Get("os")
		status := r.URL.Query().Get("status")

		filter := types.Host{
			HostInfo: types.HostInfo{
				Hostname:     hostname,
				HardwareUUID: hardwareUUID,
				Version:      version,
				Build:        build,
				OS:           os,
			},
		}

		hosts, err := db.HostRepository().RetrieveAll(filter)
		if err != nil {
			log.WithError(err).WithField("filter", filter).Info("failed to retrieve hosts")
			return err
		}

		// drop results that mismatch the status
		if status != "" {
			var temp []types.Host
			for _, h := range hosts {
				if h.Status == status {
					temp = append(temp, h)
				}
			}
			hosts = temp
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hosts)
		return nil
	}
}

func updateHost(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		return &resourceError{Message: "", StatusCode: http.StatusNotImplemented}
	}
}

func deleteHostUserRole(db repository.AASDatabase, del_h *types.Host) error {
	id := del_h.ID
	if err := db.HostRepository().Delete(*del_h); err != nil {
		log.WithError(err).WithField("id", id).Info("failed to delete host")
		return err
	}
	del_u, err := db.UserRepository().Retrieve(types.User{Name: id})
	if err != nil {
		log.WithError(err).WithField("id", id).Info("attempt to delete invalid host")
		return &resourceError{Message: "failed to delete: double check input host id",
			StatusCode: http.StatusBadRequest}
	}

	if err = db.UserRepository().Delete(*del_u); err != nil {
		log.WithError(err).WithField("id", id).Info("failed to delete user")
		return err
	}
	del_r, err := db.RoleRepository().Retrieve(types.Role{Domain: id})
	if err != nil {
		log.WithError(err).WithField("id", id).Info("attempt to delete invalid host")
		return &resourceError{Message: "failed to delete: double check input host id",
			StatusCode: http.StatusBadRequest}
	}
	if err = db.RoleRepository().Delete(*del_r); err != nil {
		log.WithError(err).WithField("id", id).Info("failed to delete role")
		return err
	}
	return nil
}
