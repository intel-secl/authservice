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

type RegHost struct {
	Flags           []string
	DatabaseFactory func() (repository.AASDatabase, error)
	ConsoleWriter   io.Writer
}

func (a RegHost) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running reghost setup...")
	envUser, _ := c.GetenvString("AAS_REG_HOST_USERNAME", "Username for register-host-user authentication")
	envPass, _ := c.GetenvSecret("AAS_REG_HOST_PASSWORD", "Password for register-host-user authentication")
	fs := flag.NewFlagSet("reghost", flag.ContinueOnError)
	username := fs.String("user", envUser, "Username for RegisterHostUser authentication")
	password := fs.String("pass", envPass, "Password for RegisterHostUser authentication")
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

	registerHostRole, err := createRole(db, consts.RegisterHostGroupName)
	if err != nil {
		return err
	}
	err = addDBUser(db, *username, *password, []types.Role{*registerHostRole})
	if err != nil {
		return err
	}
	return nil
}

func (a RegHost) Validate(c setup.Context) error {
	return nil
}
