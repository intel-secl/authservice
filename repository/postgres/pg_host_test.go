/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"os"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/stretchr/testify/assert"
)

func dialDatabase(t *testing.T) *PostgresDatabase {
	hostname := os.Getenv("POSTGRES_HOSTNAME")
	dbname := os.Getenv("POSTGRES_DB")
	user := os.Getenv("POSTGRES_USER")
	pass := os.Getenv("POSTGRE_PASSWORD")
	if hostname == "" {
		hostname = "localhost"
	}
	if dbname == "" {
		dbname = "pgdb"
	}
	if user == "" {
		user = "runner"
	}
	if pass == "" {
		pass = "test"
	}
	g, err := gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
		hostname, 5432, user, dbname, pass, "disable"))
	if err != nil {
		t.Log("Failed to dial db", err)
		t.FailNow()
	}
	return &PostgresDatabase{DB: g}
}

func createHost(hostname string, hr repository.HostRepository) (*types.Host, error) {
	host := types.Host{}
	host.Hostname = hostname
	host.HardwareUUID = "1eda8d91-fa26-44bd-85f3-283dc520e658"
	host.OS = "linux"
	host.Status = "Reserve for future implementation"
	host.Version = "1.0"
	host.Build = "1234"
	return hr.Create(host)
}

func TestHostCreate(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists  hosts cascade;")
	db.Migrate()
	created, err := createHost("10.0.0.1", db.HostRepository())
	assert.NotEmpty(created.ID)
	assert.NoError(err)
}

func TestHostCreateDuplicate(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists  hosts cascade;")
	db.Migrate()
	created, err := createHost("10.0.0.2", db.HostRepository())
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	_, err = createHost("10.0.0.2", db.HostRepository())
	// we now support duplicates
	assert.NoError(err)
}

func TestHostRetrieve(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists hosts cascade;")
	db.Migrate()
	created, err := createHost("10.0.0.3", db.HostRepository())
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	// fetch it
	fetched, err := db.HostRepository().Retrieve(types.Host{ID: created.ID})
	assert.NoError(err)
	assert.Equal(created.ID, fetched.ID)
}

func TestHostRetrieveAll(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists  hosts cascade;")
	db.Migrate()
	created, err := createHost("10.0.0.4", db.HostRepository())
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	created2, err := createHost("10.0.0.5", db.HostRepository())
	assert.NotEmpty(created2.ID)
	assert.NoError(err)

	// query all

	all, err := db.HostRepository().RetrieveAll(types.Host{})
	assert.NoError(err)
	assert.Len(all, 2)

	filter := types.Host{}
	filter.Hostname = "10.0.0.4"
	all, err = db.HostRepository().RetrieveAll(filter)
	assert.NoError(err)
	assert.Len(all, 1)
}

func TestHostUpdate(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists  hosts cascade;")
	db.Migrate()
	host := types.Host{}
	host.Hostname = "10.0.0.1"
	host.OS = "linux"
	host.Status = "Reserve for future implementation"
	host.Version = "1.0"
	host.Build = "1234"
	created, err := db.HostRepository().Create(host)
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	created.Hostname = "10.0.0.2"
	err = db.HostRepository().Update(*created)
	assert.NoError(err)
}

func TestHostDelete(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists  hosts cascade;")
	db.Migrate()
	host := types.Host{}
	host.Hostname = "10.0.0.1"
	host.OS = "linux"
	host.Status = "Reserve for future implementation"
	host.Version = "1.0"
	host.Build = "1234"
	created, err := db.HostRepository().Create(host)
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	err = db.HostRepository().Delete(*created)
	assert.NoError(err)

	all, err := db.HostRepository().RetrieveAll(types.Host{})
	assert.NoError(err)
	assert.Len(all, 0)
}

func TestHostDeleteWithReport(t *testing.T) {
	db := dialDatabase(t)
	assert := assert.New(t)
	// If you somehow run this on production, god bless your poor soul
	db.DB.Exec("DROP TABLE if exists hosts,reports cascade;")
	db.Migrate()
	host := types.Host{}
	host.Hostname = "10.0.0.1"
	host.OS = "linux"
	host.Status = "Reserve for future implementation"
	host.Version = "1.0"
	host.Build = "1234"
	created, err := db.HostRepository().Create(host)
	assert.NotEmpty(created.ID)
	assert.NoError(err)

	report := types.Report{}
	report.Detection.PID = 1
	report.HostID = created.ID
	createdReport, _ := db.ReportRepository().Create(report)

	err = db.HostRepository().Delete(*created)
	assert.NoError(err)

	all, err := db.HostRepository().RetrieveAll(types.Host{})
	assert.NoError(err)
	assert.Len(all, 0)

	f, err := db.ReportRepository().Retrieve(types.Report{ID: createdReport.ID})
	assert.NoError(err)
	assert.Zero(f.HostID)
}
