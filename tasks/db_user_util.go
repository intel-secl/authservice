/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"intel/isecl/authservice/v3/repository"
	"intel/isecl/authservice/v3/types"
	ct "intel/isecl/lib/common/v3/types/aas"
	"intel/isecl/lib/common/v3/validation"
)

// declared in pg_database.go
// var defaultLog = commLog.GetDefaultLogger()

func createPermission(db repository.AASDatabase, rule string) (*types.Permission, error) {
	defaultLog.Trace("entering tasks/createPermission")
	defer defaultLog.Trace("leaving tasks/createPermission")

	permission, err := db.PermissionRepository().Retrieve(&types.PermissionSearch{
		Rule: rule,
	})
	if err != nil {
		uuid, _ := repository.UUID()
		permission, err = db.PermissionRepository().Create(types.Permission{ID: uuid, Rule: rule})
	}
	return permission, err
}

func createRole(db repository.AASDatabase, roleCreate ct.RoleCreate) (*types.Role, error) {
	defaultLog.Trace("entering tasks/createRole")
	defer defaultLog.Trace("leaving tasks/createRole")

	var role *types.Role

	newRole := types.Role{RoleInfo: roleCreate.RoleInfo}
	role, err := db.RoleRepository().Retrieve(&types.RoleSearch{
		RoleInfo: ct.RoleInfo{Name: newRole.Name, Service: newRole.Service, Context: newRole.Context},
		AllContexts: false,
	})

	if err != nil {
		for _, rule := range roleCreate.Permissions {
			newPermRule := &types.PermissionSearch{Rule: rule}
			if existPerm, err := db.PermissionRepository().Retrieve(newPermRule); err == nil {
				newRole.Permissions = append(newRole.Permissions, *existPerm)
				continue
			} else {
				if newPerm, err := db.PermissionRepository().Create(types.Permission{Rule: rule}); err == nil {
					newRole.Permissions = append(newRole.Permissions, *newPerm)
				}
			}
		}

		newRole.ID, _ = repository.UUID()
		role, err = db.RoleRepository().Create(newRole)
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
