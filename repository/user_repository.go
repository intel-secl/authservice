/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/authservice/v3/types"
	ct "intel/isecl/lib/common/v3/types/aas"
)

type UserRepository interface {
	Create(types.User) (*types.User, error)
	Retrieve(types.User) (*types.User, error)
	RetrieveAll(user types.User) (types.Users, error)
	Update(types.User) error
	Delete(types.User) error
	GetRoles(types.User, *types.RoleSearch, bool) ([]types.Role, error)
	GetPermissions(types.User, *types.RoleSearch) ([]ct.PermissionInfo, error)
	AddRoles(types.User, types.Roles, bool) error
	GetUserRoleByID(types.User, string, []string) (types.Role, error)
	DeleteRole(types.User, string, []string) error
}
