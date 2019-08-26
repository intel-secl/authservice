/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/authservice/types"

type UserRepository interface {
	Create(types.User) (*types.User, error)
	Retrieve(types.User) (*types.User, error)
	RetrieveAll(user types.User) (types.Users, error)
	Update(types.User) error
	Delete(types.User) error
	GetRoles(types.User, *types.RoleSearch, bool) ([]types.Role, error)
	AddRoles(types.User, types.Roles, bool) error
	DeleteRole(types.User, string, []string) error
}
