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

func TestCreateRegUser(t *testing.T) {
	m := &mock.MockDatabase{}
	var user *types.User
	var role *types.Role
	m.MockUserRepository.CreateFunc = func(u types.User) (*types.User, error) {
		user = &u
		return &u, nil
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
	m.MockRoleRepository.RetrieveFunc = func(r types.Role) (*types.Role, error) {
		if role == nil {
			return nil, errors.New("Record not found")
		}
		return role, nil
	}
	task := RegHost{
		Flags: []string{"-user=regHostUser", "-pass=foobar"},
		DatabaseFactory: func() (repository.AASDatabase, error) {
			return m, nil
		},
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := task.Run(ctx)
	assert.NoError(t, err)
}
