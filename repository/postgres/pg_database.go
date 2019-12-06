/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	commLog "intel/isecl/lib/common/log"
	commLogMsg "intel/isecl/lib/common/log/message"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type PostgresDatabase struct {
	DB *gorm.DB
}

func (pd *PostgresDatabase) ExecuteSql(sql *string) error {

	defaultLog.Trace("ExecuteSql", sql)
	defer defaultLog.Trace("ExecuteSql done")

	// return pd.DB.Exec(*sql).Error
	err := pd.DB.Exec(*sql).Error
	if err != nil {
		return errors.Wrap(err, "pgdb: failed to execute sql")
	}
	return nil
}

func (pd *PostgresDatabase) ExecuteSqlFile(file string) error {

	defaultLog.Trace("ExecuteSqlFile", file)
	defer defaultLog.Trace("ExecuteSqlFile done")

	c, err := ioutil.ReadFile(file)
	if err != nil {
		// return fmt.Errorf("could not read sql file - %s, error : %s", file, err.Error())
		return errors.Wrapf(err, "could not read sql file - %s", file)
	}
	sql := string(c)
	if err := pd.ExecuteSql(&sql); err != nil {
		// return fmt.Errorf(" could not execute contents of sql file %s, error :%s", file, err.Error())
		return errors.Wrapf(err, "could not execute contents of sql file %s", file)
	}
	return nil
}

func (pd *PostgresDatabase) Migrate() error {

	defaultLog.Trace("Migrate")
	defer defaultLog.Trace("Migrate done")

	pd.DB.AutoMigrate(types.User{}, types.Role{}, types.Permission{})
	return nil
}

func (pd *PostgresDatabase) UserRepository() repository.UserRepository {
	return &PostgresUserRepository{db: pd.DB}
}

func (pd *PostgresDatabase) RoleRepository() repository.RoleRepository {
	return &PostgresRoleRepository{db: pd.DB}
}

func (pd *PostgresDatabase) PermissionRepository() repository.PermissionRepository {
	return &PostgresPermissionRepository{db: pd.DB}
}

func (pd *PostgresDatabase) Close() {
	if pd.DB != nil {
		pd.DB.Close()
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {

	defaultLog.Trace("Open DB")
	defer defaultLog.Trace("Open DB done")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 1
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			defaultLog.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		defaultLog.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		// return nil, dbErr
		secLog.Warningf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, errors.Wrapf(dbErr, "Failed to connect to db after %d attempts", numAttempts)
	}
	return &PostgresDatabase{DB: db}, nil
}

func VerifyConnection(host string, port int, dbname, user, password, sslMode, sslCert string) error {

	defaultLog.Trace("VerifyConnection")
	defer defaultLog.Trace("VerifyConnection done")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	db, dbErr := gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		host, port, user, dbname, password, sslMode, sslCertParams))

	if dbErr != nil {
		// return fmt.Errorf("could not connect to database - error : %s", dbErr.Error())
		return errors.Wrap(dbErr, "could not connect to database")
	}
	db.Close()
	return nil
}
