/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/authservice/v3/repository"
	"intel/isecl/authservice/v3/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPermissionRepository struct {
	db *gorm.DB
}

func (p *PostgresPermissionRepository) Create(permission types.Permission) (*types.Permission, error) {

	defaultLog.Trace("permission Create")
	defer defaultLog.Trace("permission Create done")

	uuid, err := repository.UUID()
	if err == nil {
		permission.ID = uuid
	} else {
		// return &permission, err
		return &permission, errors.Wrap(err, "permission create: failed to get UUID")
	}
	if err := p.db.Create(&permission).Error; err != nil {
		return &permission, errors.Wrap(err, "permission create: failed")
	}
	return &permission, nil
}

func (p *PostgresPermissionRepository) Retrieve(ps *types.PermissionSearch) (*types.Permission, error) {

	defaultLog.Trace("permission Retrieve")
	defer defaultLog.Trace("permission Retrieve done")

	tx := buildPermissionSearchQuery(p.db, ps)
	// this will always return a valid tx object. So the below check is not really needed.
	if tx == nil {
		return nil, errors.New("Unexpected Error. Could not build a gorm query object in Permissions RetrieveAll function.")
	}

	permission := &types.Permission{}
	if err := tx.First(permission).Error; err != nil {
		// return nil, err
		return nil, errors.Wrap(err, "permission retrieve: failed")
	}
	return permission, nil
}

// helper function to build the query object for a permission search.
func buildPermissionSearchQuery(tx *gorm.DB, ps *types.PermissionSearch) *gorm.DB {

	defaultLog.Trace("permission buildPermissionSearchQuery")
	defer defaultLog.Trace("permission buildPermissionSearchQuery done")

	if tx == nil {
		return nil
	}
	// check if we have a search criteria object. If we don't we have to build one so that we
	// are searching the correct table.
	if ps == nil {
		return tx.Where(&types.Permission{})
	}

	tx = tx.Where(&types.Permission{Rule: ps.Rule})

	if ps.Rule == "" && ps.RuleContains != "" {
		tx = tx.Where("rule like ? ", "%"+ps.RuleContains+"%")
	}
	if len(ps.IDFilter) > 0 {
		tx = tx.Where("id in (?) ", ps.IDFilter)
	}
	return tx

}

func (p *PostgresPermissionRepository) RetrieveAll(ps *types.PermissionSearch) (types.Permissions, error) {

	defaultLog.Trace("permission RetrieveAll")
	defer defaultLog.Trace("permission RetrieveAll done")

	var permissions types.Permissions

	tx := buildPermissionSearchQuery(p.db, ps)
	// this will always return a valid tx object. So no need to check if it
	if tx == nil {
		return permissions, errors.New("Unexpected Error. Could not build a gorm query object in Permissions RetrieveAll function.")
	}

	// defaultLog.WithField("db hosts", permissions).Trace("RetrieveAll")
	if err := tx.Find(&permissions).Error; err != nil {
		return permissions, errors.Wrap(err, "permission retrieve all: failed")
	}
	return permissions, nil
}

func (p *PostgresPermissionRepository) Update(permission types.Permission) error {
	if err := p.db.Save(&permission).Error; err != nil {
		return errors.Wrap(err, "permission update: failed")
	}
	return nil
}

func (p *PostgresPermissionRepository) Delete(permission types.Permission) error {
	if err := p.db.Delete(&permission).Error; err != nil {
		return errors.Wrap(err, "permission delete: failed")
	}
	return nil
}
