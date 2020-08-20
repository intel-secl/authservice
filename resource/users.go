/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	authcommon "intel/isecl/authservice/v3/common"
	consts "intel/isecl/authservice/v3/constants"
	"intel/isecl/authservice/v3/repository"
	"intel/isecl/authservice/v3/types"
	ct "intel/isecl/lib/common/v3/types/aas"
	"intel/isecl/lib/common/v3/validation"
	"net/http"
	"strconv"

	"github.com/gorilla/handlers"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"

	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

func SetUsers(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/users", handlers.ContentTypeHandler(createUser(db), "application/json")).Methods("POST")
	r.Handle("/users", queryUsers(db)).Methods("GET")
	r.Handle("/users/{id}", deleteUser(db)).Methods("DELETE")
	r.Handle("/users/{id}", getUser(db)).Methods("GET")
	r.Handle("/users/{id}", handlers.ContentTypeHandler(updateUser(db), "application/json")).Methods("PATCH")
	r.Handle("/users/{id}/roles", handlers.ContentTypeHandler(addUserRoles(db), "application/json")).Methods("POST")
	r.Handle("/users/{id}/roles", queryUserRoles(db)).Methods("GET")
	r.Handle("/users/{id}/permissions", queryUserPermissions(db)).Methods("GET")
	r.Handle("/users/{id}/roles/{role_id}", handlers.ContentTypeHandler(getUserRoleById(db), "application/json")).Methods("GET")
	r.Handle("/users/{id}/roles/{role_id}", handlers.ContentTypeHandler(deleteUserRole(db), "application/json")).Methods("DELETE")
}

func SetUsersNoAuth(r *mux.Router, db repository.AASDatabase) {
	r.Handle("/users/changepassword", changePassword(db)).Methods("PATCH")
}

//  declared in resource.go
//  var defaultLog = log.GetDefaultLogger()
//  var secLog = log.GetSecurityLogger()

func createUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to createUser")
		defer defaultLog.Trace("createUser return")

		var uc ct.UserCreate

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserCreate}, true)
		if err != nil {
			secLog.Warningf("%s: Unauthorized create user attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		if r.ContentLength == 0 {
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
		secLog.WithField("user", created).Infof("%s: User created by: %s", commLogMsg.UserAdded, r.RemoteAddr)

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

		defaultLog.Trace("call to getUser")
		defer defaultLog.Trace("getUser return")

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserRetrieve}, true)
		if err != nil {
			secLog.Warningf("%s: Unauthorized get user attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(u)
		if err != nil {
			// log.WithError(err).Error("failed to encode json response")
			return err
		}
		secLog.WithField("user", u).Infof("%s: Return get user request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func updateUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to updateUser")
		defer defaultLog.Trace("updateUser return")

		var uc ct.UserCreate

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserStore}, true)
		if err != nil {
			secLog.Warningf("%s: Unauthorized update user attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validationErr := validation.ValidateUUIDv4(id)
		if validationErr != nil {
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&uc)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}
		if uc.Name == "" && uc.Password == "" {
			return &resourceError{Message: "no data to change", StatusCode: http.StatusBadRequest}
		}

		// create a structure for the updated user
		updatedUser := types.User{ID: id}

		// validate user fields and set the attributes for the user that we want to change
		if uc.Name != "" {
			validationErr := validation.ValidateUserNameString(uc.Name)
			if validationErr != nil {
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
			tempUser, err := db.UserRepository().Retrieve(types.User{Name: uc.Name})
			if err == nil && tempUser.ID != id {
				defaultLog.Warningf("new username %s  for changeUser is used by user: %s", uc.Name, tempUser.ID)
				return &resourceError{Message: "supplied username belongs to another user", StatusCode: http.StatusBadRequest}
			}
			updatedUser.Name = uc.Name
		} else {
			updatedUser.Name = u.Name
		}

		if uc.Password != "" {
			validationErr = validation.ValidatePasswordString(uc.Password)
			if validationErr != nil {
				return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
			}
			updatedUser.PasswordHash, err = bcrypt.GenerateFromPassword([]byte(uc.Password), bcrypt.DefaultCost)
			if err != nil {
				defaultLog.WithError(err).Error("could not generate password when attempting to update user : ", id)
				return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
			}
			updatedUser.PasswordCost = bcrypt.DefaultCost
		} else {
			updatedUser.PasswordHash = u.PasswordHash
			updatedUser.PasswordCost = u.PasswordCost
		}

		err = db.UserRepository().Update(updatedUser)
		if err != nil {
			defaultLog.WithError(err).Error("database error while attempting to change user:", id)
			return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
		}
		secLog.Infof("%s: User %s changed by: %s", commLogMsg.PrivilegeModified, id, r.RemoteAddr)

		return nil

	}
}

func deleteUser(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to deleteUser")
		defer defaultLog.Trace("deleteUser return")

		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserDelete}, true)
		if err != nil {
			secLog.Warningf("%s: Unauthorized delete user attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		del_usr, err := db.UserRepository().Retrieve(types.User{ID: id})
		if del_usr == nil || err != nil {
			defaultLog.WithError(err).WithField("id", id).Info("attempt to delete invalid user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		if err := db.UserRepository().Delete(*del_usr); err != nil {
			// log.WithError(err).WithField("id", id).Info("failed to delete user")
			return err
		}
		secLog.WithField("user", del_usr).Infof("%s: User deleted by: %s", commLogMsg.UserDeleted, r.RemoteAddr)

		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func queryUsers(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to queryUsers")
		defer defaultLog.Trace("queryUsers return")
		// authorize rest api endpoint based on token
		_, err := AuthorizeEndpoint(r, []string{consts.UserSearch}, true)
		if err != nil {
			secLog.Warningf("%s: Unauthorized query user attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		// check for query parameters
		defaultLog.WithField("query", r.URL.Query()).Trace("query users")
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
			// log.WithError(err).WithField("filter", filter).Info("failed to retrieve users")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
		secLog.Infof("%s: Return user query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func addUserRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to addUserRoles")
		defer defaultLog.Trace("addUserRoles return")
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleCreate})
		if err != nil {
			secLog.Warningf("%s: Unauthorized add user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
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
			// log.WithError(err).Info("failed to retrieve roles")
			return &resourceError{Message: "failed to retrieve roles", StatusCode: http.StatusBadRequest}
		}

		// if the number of roles returned from the db does not match the number
		// provided in json, then abort the association(s)
		if len(roles) != len(rids.RoleUUIDs) {
			// log.Errorf("could not find matching role or user does not have authorization - requested roles - %s", rids.RoleUUIDs)
			errMsg := fmt.Sprintf("could not find matching role or user does not have authorization - requested roles - %s", rids.RoleUUIDs)
			return &resourceError{Message: errMsg, StatusCode: http.StatusBadRequest}
		}

		u, err := db.UserRepository().Retrieve(types.User{ID: id})
		if err != nil {
			// log.WithError(err).WithField("id", id).Info("failed to retrieve user")
			errMsg := fmt.Sprintf("failed to retrieve user: %s", id)
			return &resourceError{Message: errMsg, StatusCode: http.StatusBadRequest}
		}

		err = db.UserRepository().AddRoles(*u, roles, true)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}
		secLog.WithField("user", u).Infof("%s: Roles added by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)

		w.WriteHeader(http.StatusCreated) // HTTP 201
		return nil
	}
}

func queryUserRoles(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to queryUserRoles")
		defer defaultLog.Trace("queryUserRoles return")
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleSearch})
		if err != nil {
			secLog.Warningf("%s: Unauthorized query user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		// check for query parameters
		defaultLog.WithField("query", r.URL.Query()).Trace("query users")
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
			// log.WithError(err).Error("failed to retrieve user roles")
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userRoles)
		secLog.Infof("%s: Return user permission query request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func queryUserPermissions(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to queryUserRoles")
		defer defaultLog.Trace("queryUserRoles return")
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleSearch})
		if err != nil {
			secLog.Warningf("%s: Unauthorized query user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
			return err
		}

		id := mux.Vars(r)["id"]

		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		// check for query parameters
		defaultLog.WithField("query", r.URL.Query()).Trace("query users")
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

		userPermissions, err := db.UserRepository().GetPermissions(types.User{ID: id}, roleSearchFilter)
		if err != nil {
			// log.WithError(err).Error("failed to retrieve user roles")
			defaultLog.WithError(err).WithField("id", id).Error("error while obtaining permissions for user")
			return &resourceError{Message: "Database error : querying user permissions", StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userPermissions)
		secLog.Infof("%s: Return user role query request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func getUserRoleById(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to getUserRoleById")
		defer defaultLog.Trace("getUserRoleById return")
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleRetrieve})
		if err != nil {
			secLog.Warningf("%s: Unauthorized get user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
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
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
			return &resourceError{Message: "User ID provided does not exist", StatusCode: http.StatusBadRequest}
		}
		role, err := db.UserRepository().GetUserRoleByID(*u, rid, svcFltr)
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).WithField("rid", rid).Info("failed to get role from user")
			return &resourceError{Message: "Role ID provided is not associated to the User ID", StatusCode: http.StatusBadRequest}
		}
		secLog.WithField("user", *u).Infof("%s: User role found by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(role)
		return nil
	}
}

func deleteUserRole(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to deleteUserRole")
		defer defaultLog.Trace("deleteUserRole return")
		// authorize rest api endpoint based on token
		svcFltr, err := AuthorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleDelete})
		if err != nil {
			secLog.Warningf("%s: Unauthorized delete user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
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
			defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		err = db.UserRepository().DeleteRole(*u, rid, svcFltr)
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).WithField("rid", rid).Info("failed to delete role from user")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
		secLog.WithField("user", *u).Infof("%s: User roles deleted by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)

		w.WriteHeader(http.StatusNoContent) // HTTP 204
		return nil
	}
}

func changePassword(db repository.AASDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		defaultLog.Trace("call to changePassword")
		defer defaultLog.Trace("changePassword return")

		if r.ContentLength == 0 {
			return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
		}

		var pc ct.PasswordChange
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&pc)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		validation_err := validation.ValidateUserNameString(pc.UserName)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusUnauthorized}
		}

		validation_err = validation.ValidatePasswordString(pc.OldPassword)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusUnauthorized}
		}

		if pc.NewPassword != pc.PasswordConfirm {
			return &resourceError{Message: "Confirmation password does not match", StatusCode: http.StatusBadRequest}
		}

		validation_err = validation.ValidatePasswordString(pc.NewPassword)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusUnauthorized}
		}

		u := db.UserRepository()

		if httpStatus, err := authcommon.HttpHandleUserAuth(u, pc.UserName, pc.OldPassword); err != nil {
			secLog.Warningf("%s: User [%s] auth failed, requested from %s: ", commLogMsg.UnauthorizedAccess, pc.UserName, r.RemoteAddr)
			return &resourceError{Message: "", StatusCode: httpStatus}
		}

		existingUser, err := db.UserRepository().Retrieve(types.User{Name: pc.UserName})
		if err != nil {
			defaultLog.WithError(err).Error("not able to retrieve existing user though he was just authenticated")
			return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(pc.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			defaultLog.WithError(err).Error("could not generate password when attempting to change password")
			return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
		}
		existingUser.PasswordHash = passwordHash
		existingUser.PasswordCost = bcrypt.DefaultCost
		err = db.UserRepository().Update(*existingUser)
		if err != nil {
			defaultLog.WithError(err).Error("database error while attempting to change password")
			return &resourceError{Message: "cannot complete request", StatusCode: http.StatusInternalServerError}
		}
		secLog.WithField("user", existingUser.ID).Infof("%s: User %s password changed by: %s", commLogMsg.PrivilegeModified, existingUser.ID, r.RemoteAddr)

		return nil
	}

}
