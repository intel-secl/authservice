/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/authservice/v2/config"
	"intel/isecl/authservice/v2/constants"
	"intel/isecl/lib/common/v2/setup"
	"io"
	"time"

	"github.com/pkg/errors"
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
		defaultPort = constants.DefaultHttpPort
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&s.Config.Port, "port", defaultPort, "auth service http port")
	err = fs.Parse(s.Flags)
	if err != nil {
		// return err
		return errors.Wrap(err, "setup server: failed to parse cmd flags")
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

	s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
	s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
	s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins

	readTimeout, err := c.GetenvInt("AAS_SERVER_READ_TIMEOUT", "Auth Service Read Timeout")
	if err != nil {
		s.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		s.Config.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("AAS_SERVER_READ_HEADER_TIMEOUT", "Auth Service Read Header Timeout")
	if err != nil {
		s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		s.Config.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("AAS_SERVER_WRITE_TIMEOUT", "Auth Service Write Timeout")
	if err != nil {
		s.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		s.Config.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("AAS_SERVER_IDLE_TIMEOUT", "Auth Service Idle Timeout")
	if err != nil {
		s.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		s.Config.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("AAS_SERVER_MAX_HEADER_BYTES", "Auth Service Max Header Bytes Timeout")
	if err != nil {
		s.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		s.Config.MaxHeaderBytes = maxHeaderBytes
	}

	logMaxLen, err := c.GetenvInt("AAS_LOG_MAX_LENGTH", "Auth Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		s.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		s.Config.LogMaxLength = logMaxLen
	}

	logStdout, err := c.GetenvString("AAS_ENABLE_CONSOLE_LOG", "Auth Service Do not print to standard output")
	if err != nil || len(logStdout) == 0 {
		s.Config.LogEnableStdout = false
	} else {
		s.Config.LogEnableStdout = true
	}

	err = s.Config.Save()
	if err != nil {
		return errors.Wrap(err, "setup jwt: failed to save config")
	}
	return nil
}

func (s Server) Validate(c setup.Context) error {
	return nil
}
