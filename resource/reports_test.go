/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"intel/isecl/authservice/context"
	"intel/isecl/authservice/repository"
	"intel/isecl/authservice/repository/mock"
	"intel/isecl/authservice/types"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateReport(t *testing.T) {
	user_role := types.Role{
		Name: "Administrators",
	}
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	var reportCreated bool
	user_role = types.Role{
		Name:   "HostSelfUpdate",
		Domain: "22222222-2222-4222-8222-222222222222",
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()

	report := types.Report{
		HostID:       "22222222-2222-4222-8222-222222222222",
		HardwareUUID: "11111111-1111-4111-8111-111111111111",
		HostName:     "a.b.c.d",
		Detection: types.Detection{
			ProfileDescription: "description",
			PID:                1,
			TID:                2,
			ProcessName:        "process.name",
			ProcessPath:        "/usr/bin/process.name",
			Timestamp:          1234,
			Severity:           10,
			CVEIDs:             []types.CVE{types.CVE{ID: "SPECTRE1", Description: "Desc"}},
		},
	}
	db.MockReportRepository.CreateFunc = func(r types.Report) (*types.Report, error) {
		reportCreated = true
		r.ID = "11111111-1111-4111-8111-111111111111"
		r.Host = types.Host{ID: "22222222-2222-4222-8222-222222222222"}
		assert.Equal(report.Detection, r.Detection)
		return &r, nil
	}
	reportJSON, _ := json.Marshal(report)

	req := httptest.NewRequest("POST", "/aas/reports", bytes.NewBuffer(reportJSON))
	req.Header.Set("Content-Type", "application/json")
	context.SetUserRoles(req, []types.Role{user_role})
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusCreated, recorder.Code)
	assert.True(reportCreated)
}

func TestRetrieveReport(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	report := types.Report{
		ID:           "11111111-1111-4111-8111-111111111111",
		HostID:       "22222222-2222-4222-8222-222222222222",
		HardwareUUID: "11111111-1111-4111-8111-111111111111",
		HostName:     "a.b.c.d",
		Detection: types.Detection{
			ProfileDescription: "description",
			PID:                1,
			TID:                2,
			ProcessName:        "process.name",
			ProcessPath:        "/usr/bin/process.name",
			Timestamp:          1234,
			Severity:           10,
			CVEIDs:             []types.CVE{types.CVE{ID: "SPECTRE1", Description: "Desc"}},
		},
	}
	var reportRetrieved bool
	db.MockReportRepository.RetrieveFunc = func(h types.Report) (*types.Report, error) {
		reportRetrieved = true
		assert.Equal("11111111-1111-4111-8111-111111111111", h.ID)
		return &report, nil
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/reports/11111111-1111-4111-8111-111111111111", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	assert.Equal("application/json", recorder.Header().Get("Content-Type"))
	assert.True(reportRetrieved)
	assert.NotEmpty(recorder.Body.String())
}

func TestQueryReports(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	report := types.Report{
		HostID: "22222222-2222-4222-8222-222222222222",
		Detection: types.Detection{
			ProfileDescription: "description",
			PID:                1,
			TID:                2,
			ProcessName:        "process.name",
			ProcessPath:        "/usr/bin/process.name",
			Timestamp:          1234,
			Severity:           10,
			CVEIDs:             []types.CVE{types.CVE{ID: "SPECTRE1", Description: "Desc"}},
		},
	}

	db.MockReportRepository.RetrieveByFilterCriteriaFunc = func(f repository.ReportFilter) ([]types.Report, error) {
		exFrom, _ := time.Parse(time.RFC3339, "2002-10-02T15:00:00Z")
		exTo, _ := time.Parse(time.RFC3339, "2020-10-02T15:00:00Z")
		assert.Equal("10.1.2.3", f.Hostname)
		assert.Equal(exFrom, f.From)
		assert.Equal(exTo, f.To)
		return []types.Report{report}, nil
	}
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/reports?hostname=10.1.2.3&from=2002-10-02T15:00:00Z&to=2020-10-02T15:00:00Z", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
}

func TestBadQueryReports(t *testing.T) {
	assert := assert.New(t)
	db := new(mock.MockDatabase)
	r := setupRouter(db, user_role)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/aas/reports?from=NOTRFC3339", nil)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusBadRequest, recorder.Code)
	req = httptest.NewRequest("GET", "/aas/reports?to=NOTRFC3339", nil)
	recorder = httptest.NewRecorder()
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusBadRequest, recorder.Code)
}
