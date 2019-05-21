/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"time"

	"github.com/jinzhu/gorm"

	log "github.com/sirupsen/logrus"
)

type PostgresHostRepository struct {
	db *gorm.DB
}

func (r *PostgresHostRepository) Create(host types.Host) (*types.Host, error) {

	uuid, err := repository.UUID()
	if err == nil {
		host.ID = uuid
	} else {
		return &host, err
	}
	err = r.db.Create(&host).Error
	return &host, err
}

func (r *PostgresHostRepository) Retrieve(host types.Host) (*types.Host, error) {
	err := r.db.Where(&host).First(&host).Error
	log.WithField("db host", host).Trace("Retrieve")
	// if Host.Status is to be implemented into the database, disable this section
	// add 1 minute of grace period to the check
	if err == nil {
		c := config.Global()
		interval := time.Duration(c.HeartbeatIntervalMins+1) * time.Minute
		reportAfter := time.Now().Add(-interval)
		log.WithField("report after", reportAfter).Trace("Retrieve")
		fillInHostStatus(&host, reportAfter)
		return &host, nil
	}
	return nil, err
}

func (r *PostgresHostRepository) RetrieveAll(host types.Host) ([]types.Host, error) {
	var hosts []types.Host
	err := r.db.Where(&host).Find(&hosts).Error

	log.WithField("db hosts", hosts).Trace("RetrieveAll")
	// if Host.Status is to be implemented into the database, disable this section
	// add 1 minute of grace period to the check
	if err == nil {
		c := config.Global()
		interval := time.Duration(c.HeartbeatIntervalMins+1) * time.Minute
		reportAfter := time.Now().Add(-interval)
		log.WithField("report after", reportAfter).Trace("Retrieve")
		for i := 0; i < len(hosts); i++ {
			fillInHostStatus(&hosts[i], reportAfter)
		}
	}
	return hosts, err
}

func (r *PostgresHostRepository) Update(host types.Host) error {
	return r.db.Save(&host).Error
}

func (r *PostgresHostRepository) Delete(host types.Host) error {
	return r.db.Delete(&host).Error
}

// if Host.Status is to be implemented into the database, disable this function
func fillInHostStatus(h *types.Host, after time.Time) {
	if after.After(h.UpdatedAt) {
		(*h).Status = "offline"
	} else {
		(*h).Status = "online"
	}
	log.WithField("fill in", h).Trace("status")
}
