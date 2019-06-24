/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/authservice/types"
)

type MockUserRepository struct {
	CreateFunc      func(types.User) (*types.User, error)
	RetrieveFunc    func(types.User) (*types.User, error)
	RetrieveAllFunc func(types.User) (types.Users, error)
	UpdateFunc      func(types.User) error
	DeleteFunc      func(types.User) error
}

func (m *MockUserRepository) Create(user types.User) (*types.User, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(user)
	}
	return nil, nil
}

func (m *MockUserRepository) Retrieve(user types.User) (*types.User, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(user)
	}
	return nil, nil
}

func (m *MockUserRepository) RetrieveAll(u types.User) (types.Users, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(u)
	}
	return nil, nil
}

func (m *MockUserRepository) Update(user types.User) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(user)
	}
	return nil
}

func (m *MockUserRepository) Delete(user types.User) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(user)
	}
	return nil
}

func (m *MockUserRepository) GetRoles(user types.User) ([]types.Role, error) {
	return nil, nil
}

func (m *MockUserRepository) AddRoles(u types.User, roles []types.Role) error {
	return nil
}
