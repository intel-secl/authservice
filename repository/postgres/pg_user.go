/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"intel/isecl/authservice/repository"

	"intel/isecl/authservice/types"

	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type PostgresUserRepository struct {
	db *gorm.DB
}

func (r *PostgresUserRepository) Create(u types.User) (*types.User, error) {

	uuid, err := repository.UUID()
	if err == nil {
		u.ID = uuid
	} else {
		return &u, err
	}
	err = r.db.Create(&u).Error
	return &u, err
}

func (r *PostgresUserRepository) Retrieve(u types.User) (*types.User, error) {
	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *PostgresUserRepository) RetrieveAll(u types.User) (types.Users, error) {
	var users types.Users
	err := r.db.Where(&u).Find(&users).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db users", users).Trace("RetrieveAll")
	return users, err
}

func (r *PostgresUserRepository) Update(u types.User) error {
	return r.db.Save(&u).Error
}

func (r *PostgresUserRepository) Delete(u types.User) error {
	if err := r.db.Model(&u).Association("Roles").Clear().Error; err != nil {
		return err
	}
	return r.db.Delete(&u).Error
}

func (r *PostgresUserRepository) GetRolesById(u types.User) (userRoles []types.Role, err error) {
	err = r.db.Select("roles.id, roles.service, roles.name, roles.context").Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on user_roles.user_id = users.id").Where(&u).Find(&userRoles).Error
	return userRoles, err
}

func (r *PostgresUserRepository) GetRoles(u types.User) (userRoles []types.Role, err error) {
	err = r.db.Select("roles.service, roles.name, roles.context").Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on user_roles.user_id = users.id").Where(&u).Find(&userRoles).Error
	return userRoles, err
}

func (r *PostgresUserRepository) AddRoles(u types.User, roles []types.Role) error {

	// To be implemented later. We do not need this now as we are adding roles when the user is created.
	return fmt.Errorf("add roles function for user not implemented")
}
