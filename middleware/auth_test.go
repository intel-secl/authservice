/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"errors"
	"intel/isecl/authservice/repository/mock"
	"intel/isecl/authservice/types"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
)

func setupRouter() *mux.Router {
	mockRepo := &mock.MockUserRepository{
		RetrieveFunc: func(u types.User) (*types.User, error) {
			if u.Name == "username" {
				u.PasswordHash, _ = bcrypt.GenerateFromPassword([]byte("FOOBAR"), 10)
				return &u, nil
			}
			return nil, errors.New("no user")
		},
	}
	m := NewBasicAuth(mockRepo)
	r := mux.NewRouter()
	r.Use(m)
	r.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bar!"))
	})
	return r
}

func TestBasicAuth(t *testing.T) {
	assert := assert.New(t)
	r := setupRouter()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("username", "FOOBAR")
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	assert.Equal(recorder.Body.String(), "bar!")
}

func TestBasicAuthFail(t *testing.T) {
	assert := assert.New(t)
	r := setupRouter()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("username", "DEFINITELY NOT THE RIGHT PASSWORD")
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusUnauthorized, recorder.Code)
}

func TestBasicAuthWrongUser(t *testing.T) {
	assert := assert.New(t)
	r := setupRouter()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/foo", nil)
	req.SetBasicAuth("DEFINITELY NOT THE RIGHT USER", "DEFINITELY NOT THE RIGHT PASSWORD")
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusUnauthorized, recorder.Code)
}

func TestNoBasicAuth(t *testing.T) {
	assert := assert.New(t)
	r := setupRouter()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/foo", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusUnauthorized, recorder.Code)
}
