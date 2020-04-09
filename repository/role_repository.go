/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/authservice/v2/types"

type RoleRepository interface {
	Create(types.Role) (*types.Role, error)
	Retrieve(*types.RoleSearch) (*types.Role, error)
	RetrieveAll(*types.RoleSearch) (types.Roles, error)
	Update(types.Role) error
	Delete(types.Role) error
}
