/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type AASDatabase interface {
	Migrate() error
	UserRepository() UserRepository
	RoleRepository() RoleRepository
	Close()
}
