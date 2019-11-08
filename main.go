/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/authservice/constants"
	"os"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File) {

	logFile, _ = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(constants.LogFile, 0664)

	httpLogFile, _ = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(constants.HTTPLogFile, 0664)

	secLogFile, _ = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(constants.SecurityLogFile, 0664)
	return
}

func main() {
	l, h, s := openLogFiles()
	defer l.Close()
	defer h.Close()
	defer s.Close()
	app := &App{
		LogWriter:     l,
		HTTPLogWriter: h,
		SecLogWriter:  s,
	}

	err := app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
