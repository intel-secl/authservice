/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/authservice/repository"
)

type MockDatabase struct {
	MockHostRepository   MockHostRepository
	MockUserRepository   MockUserRepository
	MockRoleRepository  MockRoleRepository
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) HostRepository() repository.HostRepository {
	return &m.MockHostRepository
}

func (m *MockDatabase) UserRepository() repository.UserRepository {
	return &m.MockUserRepository
}

func (m *MockDatabase) RoleRepository() repository.RoleRepository {
	return &m.MockRoleRepository
}

func (m *MockDatabase) Close() {

}
