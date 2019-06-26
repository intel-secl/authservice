/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	. "intel/isecl/authservice/libcommon/types"
	"time"
)

type Role struct {
	ID        string    `json:"role_id,omitempty" gorm:"primary_key;type:uuid"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`

	//embed
	RoleInfo
}

type RoleIDs struct {
	RoleUUIDs []string `json:"role_ids"`
}

type Roles []Role
