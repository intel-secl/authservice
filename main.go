/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"intel/isecl/authservice/config"
	"intel/isecl/authservice/constants"
	"intel/isecl/lib/common/setup"
	"os"
	"path"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File) {
	logFilePath := path.Join(constants.LogDir, constants.LogFile)
	logFile, _ = os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(logFilePath, 0664)
	httpLogFilePath := path.Join(constants.LogDir, constants.HTTPLogFile)
	httpLogFile, _ = os.OpenFile(httpLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(httpLogFilePath, 0664)
	return
}

func main() {
	var context setup.Context
	l, h := openLogFiles()
	defer l.Close()
	defer h.Close()
	app := &App{
		LogWriter:     l,
		HTTPLogWriter: h,
	}
	// save configuration from config.yml
	loadedConfig := config.Global()
	err := loadedConfig.SaveConfiguration(context)
	if err != nil {
		fmt.Println("Error saving configuration: " + err.Error())
		os.Exit(1)
	}

	err = app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}
