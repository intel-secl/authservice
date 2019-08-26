/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	. "intel/isecl/lib/common/types/aas"
	"time"
)

type Role struct {
	ID        string    `json:"role_id,omitempty" gorm:"primary_key;type:uuid"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`

	//embed
	RoleInfo
}

type RoleSearch struct {
	//embed
	RoleInfo
	ContextContains string
	AllContexts     bool
	ServiceFilter   []string
	IDFilter        []string
}

type Roles []Role
