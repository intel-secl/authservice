/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"errors"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	ct "intel/isecl/lib/common/types/aas"
	"intel/isecl/lib/common/validation"

	"golang.org/x/crypto/bcrypt"
)

// declared in pg_database.go
// var defaultLog = commLog.GetDefaultLogger()

func createRole(db repository.AASDatabase, service, name, context string) (*types.Role, error) {

	defaultLog.Trace("entering tasks/createRole")
	defer defaultLog.Trace("leaving tasks/createRole")

	role, err := db.RoleRepository().Retrieve(&types.RoleSearch{
		RoleInfo:    ct.RoleInfo{Name: name, Service: service, Context: context},
		AllContexts: false,
	})
	if err != nil {
		uuid, _ := repository.UUID()
		role, err = db.RoleRepository().Create(types.Role{ID: uuid, RoleInfo: ct.RoleInfo{Name: name, Service: service, Context: context}})
	}
	return role, err
}

func addDBUser(db repository.AASDatabase, username string, password string, roles []types.Role) error {

	defaultLog.Trace("entering tasks/addDBUser")
	defer defaultLog.Trace("leaving tasks/addDBUser")

	if username == "" {
		return errors.New("db user setup: Username cannot be empty")
	}
	if password == "" {
		return errors.New("db user setup: Password cannot be empty")
	}
	valid_err := validation.ValidateUserNameString(username)
	if valid_err != nil {
		return valid_err
	}
	valid_err = validation.ValidatePasswordString(password)
	if valid_err != nil {
		return valid_err
	}

	userInDB, err := db.UserRepository().Retrieve(types.User{Name: username})
	userExist := (err == nil)
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	var uuid string
	if userExist {
		uuid = userInDB.ID
	} else {
		uuid, _ = repository.UUID()
	}
	err = db.UserRepository().Update(types.User{ID: uuid, Name: username, PasswordHash: hash, PasswordCost: bcrypt.DefaultCost, Roles: roles})
	if err != nil {
		defaultLog.WithError(err).Error("failed to create or update register host user in db")
		return err
	}
	return nil
}
