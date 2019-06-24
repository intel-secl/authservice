/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

type RoleInfo struct {
	Service string `json:"service,omitempty"`
	// Name: UpdateHost
	Name string `json:"name" gorm:"not null"`
	// 1234-88769876-28768
	Context string `json:"context,omitempty"`
}


