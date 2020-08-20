/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/authservice/v3/types"

type PermissionRepository interface {
	Create(types.Permission) (*types.Permission, error)
	Retrieve(*types.PermissionSearch) (*types.Permission, error)
	RetrieveAll(*types.PermissionSearch) (types.Permissions, error)
	Update(types.Permission) error
	Delete(types.Permission) error
}
