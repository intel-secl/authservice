/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

/*
import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createApp() *App {
	return &App{
		ExecutablePath: "/tmp/authservice/bin/abc",
		HomeDir:        "/tmp/authservice/",
		ConfigDir:      "/tmp/authservice/config/",
		LogDir:         "/tmp/authservice/log/",
		ExecLinkPath:   "/tmp/usr/bin/authservice",
		RunDirPath:     "/tmp/run/authservice",
	}
}

func teardownApp(a *App) {
	os.Remove(a.ConfigDir)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func TestUninstall(t *testing.T) {

	assert := assert.New(t)
	app := createApp()
	defer teardownApp(app)

	run := app.RunDirPath
	link := app.ExecLinkPath

	os.MkdirAll(app.HomeDir+"bin", os.ModeDir)
	os.MkdirAll(app.ConfigDir, os.ModeDir)
	os.MkdirAll(app.LogDir, os.ModeDir)
	os.MkdirAll("/run", os.ModeDir)
	os.MkdirAll("/usr/bin/", os.ModeDir)

	f1, _ := os.Create(app.ExecutablePath)
	f2, _ := os.Create(app.ConfigDir + "config")
	f3, _ := os.Create(app.LogDir + "log")
	f4, _ := os.Create(run)

	f1.Close()
	f2.Close()
	f3.Close()
	f4.Close()

	os.Symlink(run, link)

	app.Run([]string{"authservice", "uninstall"})

	exist, err := exists(app.HomeDir)
	assert.Equal(nil, err)
	assert.False(exist)

	exist, err = exists(app.ConfigDir)
	assert.Equal(nil, err)
	assert.False(exist)

	exist, err = exists(app.LogDir)
	assert.Equal(nil, err)
	assert.False(exist)

	exist, err = exists(app.ExecutablePath)
	assert.Equal(nil, err)
	assert.False(exist)

	exist, err = exists(run)
	assert.Equal(nil, err)
	assert.False(exist)

	exist, err = exists(link)
	assert.Equal(nil, err)
	assert.False(exist)
}
*/
