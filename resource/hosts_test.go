/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"errors"
	"intel/isecl/authservice/repository/mock"
	"intel/isecl/authservice/types"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateHost(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	var hostCreated bool
	db.MockHostRepository.CreateFunc = func(h types.Host) (*types.Host, error) {
		hostCreated = true
		h.ID = "12345"
		h.HardwareUUID = "1eda8d91-fa26-44bd-85f3-283dc520e658"
		assert.Equal("host.intel.com", h.Hostname)
		assert.Equal("v1.0", h.Version)
		assert.Equal("1234", h.Build)
		assert.Equal("linux", h.OS)
		assert.Equal("1eda8d91-fa26-44bd-85f3-283dc520e658", h.HardwareUUID)
		return &h, nil
	}
	user_role = types.Role{
		Name: "Administrators",
	}
	db.MockUserRepository.CreateFunc = func(u types.User) (*types.User, error) {
		u.PasswordHash, _ = bcrypt.GenerateFromPassword([]byte("password"), 10)
		u.Roles = []types.Role{user_role}
		return &u, nil
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/aas/hosts", bytes.NewBufferString(`{"hostname": "host.intel.com","hardware_uuid" : "1eda8d91-fa26-44bd-85f3-283dc520e658", "version": "v1.0", "build": "1234", "os":"linux"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusCreated, recorder.Code)
	assert.Equal("application/json", recorder.Header().Get("Content-Type"))
	assert.True(hostCreated)
}

func TestRetrieveHost(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	var hostRetrieved bool
	db.MockHostRepository.RetrieveFunc = func(h types.Host) (*types.Host, error) {
		hostRetrieved = true
		assert.Equal("12345", h.ID)
		return &types.Host{
			ID: "12345",
			HostInfo: types.HostInfo{
				HardwareUUID: "1eda8d91-fa26-44bd-85f3-283dc520e658",
				Version:      "v1.0",
				Build:        "1234",
				OS:           "linux",
			},
			Status: "",
		}, nil
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/hosts/12345", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	assert.Equal("application/json", recorder.Header().Get("Content-Type"))
	assert.True(hostRetrieved)
	assert.NotEmpty(recorder.Body.String())
}

func TestRetrieveHost404(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	db.MockHostRepository.RetrieveFunc = func(h types.Host) (*types.Host, error) {
		return nil, gorm.ErrRecordNotFound
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/hosts/12345", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusNotFound, recorder.Code)
}

func TestDeleteHost(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	id := "12345"
	var hostDeleted bool
	var roleDeleted bool
	var userDeleted bool

	testHost := types.Host{ID: id}
	testRole := types.Role{Domain: id}
	testUser := types.User{Name: id}

	db.MockHostRepository.RetrieveFunc = func(h types.Host) (*types.Host, error) {

		if id == h.ID {
			return &testHost, nil
		}
		return &h, errors.New("record not found")
	}
	db.MockRoleRepository.RetrieveFunc = func(r types.Role) (*types.Role, error) {

		if id == r.Domain {
			return &testRole, nil
		}
		return &r, errors.New("record not found")
	}
	db.MockUserRepository.RetrieveFunc = func(u types.User) (*types.User, error) {

		if id == u.Name {
			return &testUser, nil
		}
		return &u, errors.New("record not found")
	}
	db.MockHostRepository.DeleteFunc = func(h types.Host) error {

		if id == h.ID {
			hostDeleted = true
			return nil
		}
		return errors.New("record not found")
	}
	db.MockRoleRepository.DeleteFunc = func(r types.Role) error {

		if id == r.Domain {
			roleDeleted = true
			return nil
		}
		return errors.New("record not found")
	}
	db.MockUserRepository.DeleteFunc = func(u types.User) error {

		if id == u.Name {
			userDeleted = true
			return nil
		}
		return errors.New("record not found")
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/aas/hosts/12345", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusNoContent, recorder.Code)
	assert.True(hostDeleted)
	assert.True(roleDeleted)
	assert.True(userDeleted)

	req2 := httptest.NewRequest("DELETE", "/aas/hosts/99999", nil)
	recorder2 := httptest.NewRecorder()
	r.ServeHTTP(recorder2, req2)
	assert.Equal(http.StatusBadRequest, recorder2.Code)
}

func TestDeleteHost404(t *testing.T) {

	assert := assert.New(t)
	db := new(mock.MockDatabase)
	db.MockHostRepository.DeleteFunc = func(h types.Host) error {
		return gorm.ErrRecordNotFound
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/aas/hosts/12345", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusBadRequest, recorder.Code)
}

func TestQueryHosts(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	filter := types.Host{
		HostInfo: types.HostInfo{
			Hostname: "10.1.2.3",
			Version:  "1.0",
			Build:    "1234",
			OS:       "linux",
		},
		Status: "",
	}
	db.MockHostRepository.RetrieveAllFunc = func(h types.Host) ([]types.Host, error) {
		assert.Equal(filter, h)
		h.ID = "12345"
		return []types.Host{h}, nil
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/hosts?hostname=10.1.2.3&version=1.0&build=1234&os=linux", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	// setup expected
	filter.ID = "12345"
	expected := []types.Host{filter}
	var actual []types.Host
	json.Unmarshal(recorder.Body.Bytes(), &actual)
	assert.Equal(expected, actual)
}
