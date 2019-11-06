/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/authservice/types"
)

type MockPermissionRepository struct {
	CreateFunc      func(types.Permission) (*types.Permission, error)
	RetrieveFunc    func(*types.PermissionSearch) (*types.Permission, error)
	RetrieveAllFunc func(*types.PermissionSearch) (types.Permissions, error)
	UpdateFunc      func(types.Permission) error
	DeleteFunc      func(types.Permission) error
}

func (m *MockPermissionRepository) Create(permission types.Permission) (*types.Permission, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(permission)
	}
	return nil, nil
}

func (m *MockPermissionRepository) Retrieve(rs *types.PermissionSearch) (*types.Permission, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(rs)
	}
	return nil, nil
}

func (m *MockPermissionRepository) RetrieveAll(rs *types.PermissionSearch) (types.Permissions, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(rs)
	}
	return nil, nil
}

func (m *MockPermissionRepository) Update(permission types.Permission) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(permission)
	}
	return nil
}

func (m *MockPermissionRepository) Delete(permission types.Permission) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(permission)
	}
	return nil
}
