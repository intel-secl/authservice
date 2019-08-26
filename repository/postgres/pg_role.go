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

func (r *PostgresRoleRepository) Retrieve(rs *types.RoleSearch) (*types.Role, error) {

	tx := buildRoleSearchQuery(r.db, rs)
	// this will always return a valid tx object. So the below check is not really needed.
	if tx == nil {
		return nil, fmt.Errorf("Unexpected Error. Could not build a gorm query object in Roles RetrieveAll function. ")
	}

	role := &types.Role{}
	err := tx.First(role).Error
	if err != nil {
		return nil, err
	}
	return role, nil
}

// helper function to build the query object for a role search.
func buildRoleSearchQuery(tx *gorm.DB, rs *types.RoleSearch) *gorm.DB {

	if tx == nil {
		return nil
	}
	// check if we have a search criteria object. If we don't we have to build one so that we
	// are searching the correct table.
	if rs == nil {
		return tx.Where(&types.Role{})
	}

	tx = tx.Where(&types.Role{RoleInfo: rs.RoleInfo})

	// Are we looking for roles that have values in the context field. If we only roles that does not have
	// context, then the `AllContext` field would be set to false.
	if rs.AllContexts == true {
		// We are looking for substring match. However, if the context field is non empty, this takes
		// precedence and the ContextContains is ignored.
		if rs.Context == "" && rs.ContextContains != "" {
			tx = tx.Where("context like ? ", "%"+rs.ContextContains+"%")
		}
	} else {
		// AllContexts is false - we only want records where the service and name match and the context
		// field is empty
		if rs.Context == "" {
			tx = tx.Where("context = ''")
		}
	}

	if len(rs.IDFilter) > 0 {
		tx = tx.Where("id in (?) ", rs.IDFilter)
	}
	if len(rs.ServiceFilter) > 0 {
		tx = tx.Where("service in (?) ", rs.ServiceFilter)
	}
	return tx

}

func (r *PostgresRoleRepository) RetrieveAll(rs *types.RoleSearch) (types.Roles, error) {
	var roles types.Roles

	tx := buildRoleSearchQuery(r.db, rs)
	// this will always return a valid tx object. So no need to check if it
	if tx == nil {
		return roles, fmt.Errorf("Unexpected Error. Could not build a gorm query object in Roles RetrieveAll function. ")
	}
	err := tx.Find(&roles).Error

	log.WithField("db hosts", roles).Trace("RetrieveAll")
	return roles, err
}

func (r *PostgresRoleRepository) Update(role types.Role) error {
	return r.db.Save(&role).Error
}

func (r *PostgresRoleRepository) Delete(role types.Role) error {
	return r.db.Delete(&role).Error
}
