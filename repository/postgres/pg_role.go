/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"

	"github.com/jinzhu/gorm"
)

type PostgresRoleRepository struct {
	db *gorm.DB
}

func (r *PostgresRoleRepository) Create(role types.Role) (*types.Role, error) {

	uuid, err := repository.UUID()
	if err == nil {
		role.ID = uuid
	} else {
		return &role, err
	}
	err = r.db.Create(&role).Error
	return &role, err
}

func (r *PostgresRoleRepository) Retrieve(role types.Role) (*types.Role, error) {
	err := r.db.Where(&role).First(&role).Error
	return &role, err
}

func (r *PostgresRoleRepository) Update(role types.Role) error {
	return r.db.Save(&role).Error
}

func (r *PostgresRoleRepository) Delete(role types.Role) error {
	return r.db.Delete(&role).Error
}
