/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"bytes"
	"fmt"
	"time"

	"intel/isecl/lib/common/crypt"
	"intel/isecl/authservice/constants"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string     `gorm:"primary_key;type:uuid"`
	CreatedAt    time.Time  `json:"-"`
	UpdatedAt    time.Time  `json:"-"`
	DeletedAt    *time.Time `json:"-"`
	Name         string
	PasswordHash []byte
	Roles        []Role `gorm:"many2many:user_roles"`
}

func (u *User) CheckPassword(password []byte) error {
	return bcrypt.CompareHashAndPassword(u.PasswordHash, password)
}

func (u *User) ValidateToken(token []byte, serverRand []byte) error {

	hash, err := crypt.GetHashData(append(u.PasswordHash, serverRand...), constants.HashingAlgorithm)
	if err != nil {
		return err
	}
	if bytes.Equal(token, hash) {
		return nil
	}
	return fmt.Errorf("token not validated ")
}
