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
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/setup"
	"io"

	"github.com/pkg/errors"

	commLogMsg "intel/isecl/lib/common/log/message"
)

type Admin struct {
	Flags           []string
	DatabaseFactory func() (repository.AASDatabase, error)
	ConsoleWriter   io.Writer
}

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a Admin) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")
	envUser, _ := c.GetenvString("AAS_ADMIN_USERNAME", "Username for admin authentication")
	envPass, _ := c.GetenvSecret("AAS_ADMIN_PASSWORD", "Password for admin authentication")
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	username := fs.String("user", envUser, "Username for admin authentication")
	password := fs.String("pass", envPass, "Password for admin authentication")
	err := fs.Parse(a.Flags)
	if err != nil {
		// return err
		return errors.Wrap(err, "setup admin: failed to parse cmd flags")
	}
	db, err := a.DatabaseFactory()
	if err != nil {
		defaultLog.WithError(err).Error("failed to open database")
		return errors.Wrap(err, "setup admin: failed to open database")
	}
	defer db.Close()

	var adminRoles types.Roles

	for _, roleCreate := range consts.GetDefaultAdministratorRoles() {
		role, err := createRole(db, roleCreate)
		if err != nil {
			return errors.Wrapf(err, "setup admin: could not create role in database - error %v", err)
		}
		adminRoles = append(adminRoles, *role)
	}

	err = addDBUser(db, *username, *password, adminRoles)
	if err != nil {
		// return err
		return errors.Wrap(err, "setup admin: failed to open add db user")
	}
	secLog.Infof("%s: Finished setup for admin %s:", commLogMsg.UserAdded, *username)
	secLog.Infof("%s: Finished setup for admin %s:", commLogMsg.PrivilegeModified, *username)
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
