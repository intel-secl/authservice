/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/authservice/types"
	"time"
)

type ReportFilter struct {
	types.Report
	Hostname     string
	From         time.Time
	To           time.Time
	HardwareUUID string
}

type ReportRepository interface {
	// everything should take a non pointer struct and Create should return a pointer
	Create(report types.Report) (*types.Report, error)
	Retrieve(report types.Report) (*types.Report, error)
	RetrieveAll(report types.Report) ([]types.Report, error)
	RetrieveByFilterCriteria(filter ReportFilter) ([]types.Report, error)
	Update(report types.Report) error
	Delete(report types.Report) error
}
