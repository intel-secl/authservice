/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/authservice/types"

type RoleRepository interface {
	Create(types.Role) (*types.Role, error)
	Retrieve(types.Role) (*types.Role, error)
	Update(types.Role) error
	Delete(types.Role) error
}