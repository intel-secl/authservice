/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"errors"
	"regexp"

	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

var (
	roleNameReg    = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,40}$`)
	serviceNameReg = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,20}$`)
	contextReg     = regexp.MustCompile(`^[A-Za-z0-9-_/.@,=;: *]{0,512}$`)
	aasUsernameReg = regexp.MustCompile(`^[A-Za-z0-9-_/.@*]{1,255}$`)
	aasPasswordReg = regexp.MustCompile(`^.{1,255}$`)
)

//  declared in resource.go
//  var defaultLog = log.GetDefaultLogger()
//  var secLog = log.GetSecurityLogger()

// ValidateRoleString is used to check if the string is a valid AAS role string
func ValidateRoleString(roleString string) error {
	if !roleNameReg.MatchString(roleString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid role string provided")
	}

	return nil
}

// ValidateServiceString is used to check if the string is a valid AAS service string
func ValidateServiceString(serviceString string) error {
	if !serviceNameReg.MatchString(serviceString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid service string provided")
	}

	return nil
}

// ValidateContextString is used to check if the string is a valid AAS context string
func ValidateContextString(contextString string) error {
	if !contextReg.MatchString(contextString) {
		secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
		return errors.New("Invalid context string provided")
	}

	return nil
}

// ValidatePermissionsString is used to check if the string is a valid AAS context string
func ValidatePermissions(permissions []string) error {

	for i, _ := range permissions {
		if len(permissions[i]) > 512 {
			secLog.Warning(commLogMsg.InvalidInputProtocolViolation)
			return errors.New("Invalid Permissions string provided. Max 512 charecters allowed per permission")
		}
	}

	return nil
}
