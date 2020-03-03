/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"intel/isecl/lib/common/setup"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/repository/mock"
	"intel/isecl/authservice/types"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAdmin(t *testing.T) {
	m := &mock.MockDatabase{}
	var user *types.User
	var role *types.Role
	var permission *types.Permission
	m.MockUserRepository.CreateFunc = func(u types.User) (*types.User, error) {
		user = &u
		return user, nil
	}
	m.MockUserRepository.RetrieveFunc = func(u types.User) (*types.User, error) {
		if user == nil {
			return nil, errors.New("Record not found")
		}
		return user, nil
	}
	m.MockRoleRepository.CreateFunc = func(r types.Role) (*types.Role, error) {
		role = &r
		return role, nil
	}
	m.MockRoleRepository.RetrieveFunc = func(r *types.RoleSearch) (*types.Role, error) {
		if role == nil {
			return nil, errors.New("Record not found")
		}
		return role, nil
	}
	m.MockPermissionRepository.CreateFunc = func(p types.Permission) (*types.Permission, error) {
		permission = &p
		return permission, nil
	}
	m.MockPermissionRepository.RetrieveFunc = func(r *types.PermissionSearch) (*types.Permission, error) {
		if permission == nil {
			return nil, errors.New("Record not found")
		}
		return permission, nil
	}

	task := Admin{
		Flags: []string{"-user=admin", "-pass=foobarfoobar"},
		DatabaseFactory: func() (repository.AASDatabase, error) {
			return m, nil
		},
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := task.Run(ctx)
	assert.NoError(t, err)
}
