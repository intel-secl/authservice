/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	consts "intel/isecl/authservice/constants"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/types"
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

	adminRole, err := createRole(db, consts.AdminGroupName)
	if err != nil {
		return err
	}
	err = addDBUser(db, *username, *password, []types.Role{*adminRole})
	if err != nil {
		return err
	}
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
