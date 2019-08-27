/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"strings"
	"testing"

	"intel/isecl/lib/common/validation"

	"github.com/stretchr/testify/assert"
)

func TestValidateRoleString(t *testing.T) {

	err := ValidateRoleString("administrator")
	assert.NoError(t, err)

	err = ValidateRoleString("") // empty, not ok
	assert.Error(t, err)

	err = ValidateRoleString(strings.Repeat("a", 40)) // 40 or less, ok
	assert.NoError(t, err)

	err = ValidateRoleString(strings.Repeat("a", 41)) // more than 40, not ok
	assert.Error(t, err)

	err = ValidateRoleString("administrator-at-large") // dashes ok
	assert.NoError(t, err)

	err = ValidateRoleString("administrator.at.large") // dots ok
	assert.NoError(t, err)

	err = ValidateRoleString("kahuna,big") // comma ok
	assert.NoError(t, err)

	err = ValidateRoleString("big@kahuna.com")
	assert.NoError(t, err)

}

func TestValidateServiceString(t *testing.T) {

	err := ValidateServiceString("AAS")
	assert.NoError(t, err)

	err = ValidateServiceString("") // empty, not ok
	assert.Error(t, err)

	err = ValidateServiceString(strings.Repeat("a", 20)) // 20 or less, ok
	assert.NoError(t, err)

	err = ValidateServiceString(strings.Repeat("a", 21)) // more than 20, not ok
	assert.Error(t, err)

	err = ValidateServiceString("service-name") // dashes ok
	assert.NoError(t, err)

	err = ValidateServiceString("service.name") // dots ok
	assert.NoError(t, err)

	err = ValidateServiceString("name,service") // comma ok
	assert.NoError(t, err)

	err = ValidateServiceString("service@name.com")
	assert.NoError(t, err)
}

func TestValidateContextString(t *testing.T) {

	err := ValidateContextString("") // empty is ok
	assert.NoError(t, err)

	err = ValidateContextString(strings.Repeat("a", 512)) // 512 len is ok
	assert.NoError(t, err)

	err = ValidateContextString(strings.Repeat("a", 513)) // Longer than 512 is not ok
	assert.Error(t, err)

	err = ValidateContextString("cn=John Doe, ou=People, dc=*.intel.com") // ex distinguished name
	assert.NoError(t, err)
}

func TestValidateUserNameString(t *testing.T) {

	err := validation.ValidateUserNameString("") // empty is not ok
	assert.Error(t, err)

	err = validation.ValidateUserNameString(strings.Repeat("a", 255)) // 255 len is ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString(strings.Repeat("a", 256)) // Longer than 255 is not ok
	assert.Error(t, err)

	err = validation.ValidateUserNameString("george")
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george of the jungle") // no spaces
	assert.Error(t, err)

	err = validation.ValidateUserNameString("george-of-the-jungle") // dashes ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george.of.the.jungle") // dots ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george@thejungle.com") // email
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("`~!@#$%^&*()-=_+[]{}\\|;:'\",<.>/?") // no other characters
	assert.Error(t, err)
}

func TestValidatePasswordString(t *testing.T) {

	err := validation.ValidatePasswordString("") // empty is not ok
	assert.Error(t, err)

	err = validation.ValidatePasswordString(strings.Repeat("a", 255)) // 255 len is ok
	assert.NoError(t, err)

	err = validation.ValidatePasswordString(strings.Repeat("a", 256)) // Longer than 255 is not ok
	assert.Error(t, err)

	// no restriction on characters...
	err = validation.ValidatePasswordString("`~!@#$%^&*()_+1234567890-={}[]\\|:;'\",./<>?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	assert.NoError(t, err)
}
