/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	consts "intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
	"intel/isecl/lib/common/setup"
	"io"

	log "github.com/sirupsen/logrus"
)

type Admin struct {
	Flags           []string
	DatabaseFactory func() (repository.AASDatabase, error)
	ConsoleWriter   io.Writer
}

func (a Admin) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")
	envUser, _ := c.GetenvString("AAS_ADMIN_USERNAME", "Username for admin authentication")
	envPass, _ := c.GetenvSecret("AAS_ADMIN_PASSWORD", "Password for admin authentication")
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	username := fs.String("user", envUser, "Username for admin authentication")
	password := fs.String("pass", envPass, "Password for admin authentication")
	err := fs.Parse(a.Flags)
	if err != nil {
		return err
	}
	db, err := a.DatabaseFactory()
	if err != nil {
		log.WithError(err).Error("failed to open database")
		return err
	}
	defer db.Close()

	var adminRoles types.Roles

	for _, roleName := range consts.GetDefaultAdministratorRoles() {
		role, err := createRole(db, consts.ServiceName, roleName, "")
		if err != nil {
			return fmt.Errorf("could not create role in database - error %v", err)
		}
		adminRoles = append(adminRoles, *role)
	}

	err = addDBUser(db, *username, *password, adminRoles)
	if err != nil {
		return err
	}
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
