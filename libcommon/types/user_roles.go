/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

type UserRole struct {
	// Name: UpdateHost
	Service string `json:"service,omitempty"`
	Name    string `json:"name"`
	Scope   string `json:"scope,omitempty"`
}

type UserRoles struct {
	Roles []UserRole `json:"roles"`
}

type UserCred struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
}
