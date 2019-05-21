/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import "time"

type HostInfo struct {
	Hostname     string `json:"hostname"`
	HardwareUUID string `json:"hardware_uuid"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	OS           string `json:"os"`
}

type Host struct {
	ID        string    `json:"id" gorm:"primary_key;type:uuid"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
	// embed
	HostInfo
	// tag gorm:"-" will have the DB ignore this field
	Status string `json:"status" gorm:"-"`
}

type HostCreateResponse struct {
	Host
	User  string `json:"user"`
	Token string `json:"token"`
}

type HostHeartbeat struct {
	ID           string `json:"id"`
	IntervalMins uint16 `json:"interval"`
}
