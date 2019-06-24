/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

type RoleSlice struct {
	Roles []RoleInfo `json:"roles"`
}

type UserCred struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}
