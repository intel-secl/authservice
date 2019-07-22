/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"flag"
	"fmt"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/lib/common/setup"
	"io"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (s Server) Run(c setup.Context) error {
	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("AAS_PORT", "auth service http port")
	if err != nil {
		defaultPort = 8443
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&s.Config.Port, "port", defaultPort, "auth service http port")
	err = fs.Parse(s.Flags)
	if err != nil {
		return err
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

	s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
	s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
	s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins

	s.Config.HeartbeatIntervalMins = constants.DefaultHeartbeatInt

	return s.Config.Save()
}

func (s Server) Validate(c setup.Context) error {
	return nil
}
