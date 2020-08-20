/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/authservice/v3/types"
)

type MockRoleRepository struct {
	CreateFunc      func(types.Role) (*types.Role, error)
	RetrieveFunc    func(*types.RoleSearch) (*types.Role, error)
	RetrieveAllFunc func(*types.RoleSearch) (types.Roles, error)
	UpdateFunc      func(types.Role) error
	DeleteFunc      func(types.Role) error
}

func (m *MockRoleRepository) Create(role types.Role) (*types.Role, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(role)
	}
	return nil, nil
}

func (m *MockRoleRepository) Retrieve(rs *types.RoleSearch) (*types.Role, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(rs)
	}
	return nil, nil
}

func (m *MockRoleRepository) RetrieveAll(rs *types.RoleSearch) (types.Roles, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(rs)
	}
	return nil, nil
}

func (m *MockRoleRepository) Update(role types.Role) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(role)
	}
	return nil
}

func (m *MockRoleRepository) Delete(role types.Role) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(role)
	}
	return nil
}
