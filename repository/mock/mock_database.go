/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/authservice/v2/repository"
)

type MockDatabase struct {
	MockUserRepository       MockUserRepository
	MockRoleRepository       MockRoleRepository
	MockPermissionRepository MockPermissionRepository
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) UserRepository() repository.UserRepository {
	return &m.MockUserRepository
}

func (m *MockDatabase) RoleRepository() repository.RoleRepository {
	return &m.MockRoleRepository
}

func (m *MockDatabase) PermissionRepository() repository.PermissionRepository {
	return &m.MockPermissionRepository
}

func (m *MockDatabase) Close() {

}
