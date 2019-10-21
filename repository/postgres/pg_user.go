/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/authservice/repository"

	"intel/isecl/authservice/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresUserRepository struct {
	db *gorm.DB
}

// declared in pg_database.go
// var defaultLog = commLog.GetDefaultLogger()

func (r *PostgresUserRepository) Create(u types.User) (*types.User, error) {

	defaultLog.Trace("user Create")
	defer defaultLog.Trace("user Create done")

	uuid, err := repository.UUID()
	if err == nil {
		u.ID = uuid
	} else {
		// return &u, err
		return &u, errors.Wrap(err, "user create: failed to get UUID")
	}
	err = r.db.Create(&u).Error
	if err != nil {
		return &u, errors.Wrap(err, "user create: failed")
	}
	return &u, nil
	// return &u, err
}

func (r *PostgresUserRepository) Retrieve(u types.User) (*types.User, error) {

	defaultLog.Trace("user Retrieve")
	defer defaultLog.Trace("user Retrieve done")

	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		// return nil, err
		return nil, errors.Wrap(err, "user retrieve: failed")
	}
	return &u, nil
}

func (r *PostgresUserRepository) RetrieveAll(u types.User) (types.Users, error) {

	defaultLog.Trace("user RetrieveAll")
	defer defaultLog.Trace("user RetrieveAll done")

	var users types.Users
	err := r.db.Where(&u).Find(&users).Error
	if err != nil {
		return nil, errors.Wrap(err, "user retrieve: failed")
	}
	// defaultLog.WithField("db users", users).Trace("RetrieveAll")
	return users, nil
}

func (r *PostgresUserRepository) Update(u types.User) error {
	err := r.db.Save(&u).Error
	if err != nil {
		return errors.Wrap(err, "user update: failed")
	}
	return nil
}

func (r *PostgresUserRepository) Delete(u types.User) error {

	defaultLog.Trace("user Delete")
	defer defaultLog.Trace("user Delete done")
	if err := r.db.Model(&u).Association("Roles").Clear().Error; err != nil {
		return errors.Wrap(err, "user delete: failed to clear user-role mapping")
	}
	// return r.db.Delete(&u).Error
	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "user delete: failed to clear user-role mapping")
	}
	return nil
}

func (r *PostgresUserRepository) GetRoles(u types.User, rs *types.RoleSearch, includeID bool) (userRoles []types.Role, err error) {

	defaultLog.Trace("user GetRoles")
	defer defaultLog.Trace("user GetRoles done")

	var cols string

	if includeID {
		cols = "roles.id, "
	}
	cols = cols + "roles.service, roles.name, roles.context"
	tx := r.db.Select(cols).Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on user_roles.user_id = users.id").Where(&u)

	if rs != nil {
		tx = buildRoleSearchQuery(tx, rs)
	}
	if err := tx.Find(&userRoles).Error; err != nil {
		return userRoles, errors.Wrap(err, "user delete: failed to clear user-role mapping")
	}
	return userRoles, nil
}

func (r *PostgresUserRepository) AddRoles(u types.User, roles types.Roles, mustAddAllRoles bool) error {

	defaultLog.Trace("user AddRoles")
	defer defaultLog.Trace("user AddRoles done")

	// defaultLog.Trace("Adding role User:", u, "Roles:", roles)
	if err := r.db.Model(&u).Association("Roles").Append(roles).Error; err != nil {
		return errors.Wrap(err, "user add roles: failed")
	}
	return nil
}

func (r *PostgresUserRepository) DeleteRole(u types.User, roleID string, svcFltr []string) error {

	defaultLog.Trace("user DeleteRole")
	defer defaultLog.Trace("user DeleteRole done")

	var role types.Role
	tx := r.db.Where("id IN (?) ", roleID)
	if len(svcFltr) > 0 {
		tx = tx.Where("service in (?) ", svcFltr)
	}

	// lets sanitize the list with roles that already exists in the database.
	err := tx.Find(&role).Error
	if err != nil {
		// return fmt.Errorf("could not find role id:%s in database", roleID)
		return errors.Wrapf(err, "user delete roles: could not find role id %s in database", roleID)
	}
	if err = r.db.Model(&u).Association("Roles").Delete(role).Error; err != nil {
		return errors.Wrap(err, "user delete role: failed")
	}
	return nil
}
