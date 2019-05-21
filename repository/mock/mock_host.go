/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import "intel/isecl/authservice/types"

type MockHostRepository struct {
	CreateFunc      func(types.Host) (*types.Host, error)
	RetrieveFunc    func(types.Host) (*types.Host, error)
	RetrieveAllFunc func(types.Host) ([]types.Host, error)
	UpdateFunc      func(types.Host) error
	DeleteFunc      func(types.Host) error
}

func (m *MockHostRepository) Create(host types.Host) (*types.Host, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(host)
	}
	return nil, nil
}

func (m *MockHostRepository) Retrieve(host types.Host) (*types.Host, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(host)
	}
	return nil, nil
}

func (m *MockHostRepository) RetrieveAll(host types.Host) ([]types.Host, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(host)
	}
	return nil, nil
}

func (m *MockHostRepository) Update(host types.Host) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(host)
	}
	return nil
}

func (m *MockHostRepository) Delete(host types.Host) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(host)
	}
	return nil
}
