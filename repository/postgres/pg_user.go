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

func (r *PostgresUserRepository) GetRoles(u types.User, roleFilter *types.Role, includeID bool) (userRoles []types.Role, err error) {
	var cols string
	if includeID {
		cols = "roles.id, "
	}

	cols = cols + "roles.service, roles.name, roles.context"
	tx := r.db.Select(cols).Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on user_roles.user_id = users.id").Where(&u)

	if roleFilter != nil {
		tx = tx.Where(roleFilter)
	}

	err = tx.Find(&userRoles).Error

	return userRoles, err
}

func (r *PostgresUserRepository) AddRoles(u types.User, roleList types.RoleIDs, mustAddAllRoles bool) error {

	var roles types.Roles
	fmt.Println("Inside pg_user add role fn")
	// lets sanitize the list with roles that already exists in the database.
	err := r.db.Where("id IN (?)", roleList.RoleUUIDs).Find(&roles).Error
	if err != nil {
		return err
	}

	// if the list of roles retrieved does not match the requested roles, we will return an error for now
	// TODO: we should be able to gracefully handle the scenario and add only the roles that was found in
	// the database and return an appropriate error object that the client can make a decision on. We might
	//
	if mustAddAllRoles && len(roleList.RoleUUIDs) != len(roles) {
		log.Errorf("number of retrieved roles : %d, requested roles %v", len(roleList.RoleUUIDs), roleList.RoleUUIDs)
		log.Infof("roles found in db: %v", roles)
		return fmt.Errorf("mismatch between requested number of roles to be added and roles found in db")
	}
	fmt.Println("Inside pg_user about to append role")
	if err = r.db.Model(&u).Association("Roles").Append(roles).Error; err != nil {
		return err
	}

	return nil
}

func (r *PostgresUserRepository) DeleteRole(u types.User, roleID string) error {

	var role types.Role

	// lets sanitize the list with roles that already exists in the database.
	err := r.db.Where("id IN (?) ", roleID).Find(&role).Error
	if err != nil {
		return fmt.Errorf("could not find role id:%s in database", roleID)
	}

	if err = r.db.Model(&u).Association("Roles").Delete(role).Error; err != nil {
		return err
	}

	return nil
}
