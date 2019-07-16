/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	 "errors"
	 "regexp"
 )
 
 var (
	 roleNameReg      = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,40}$`)
	 serviceNameReg   = regexp.MustCompile(`^[A-Za-z0-9-_/.@,]{1,20}$`)
	 contextReg       = regexp.MustCompile(`^[A-Za-z0-9-_/.@,=; *]{0,512}$`)
	 aasUsernameReg   = regexp.MustCompile(`^[A-Za-z0-9-_/.@*]{1,255}$`)
	 aasPasswordReg   = regexp.MustCompile(`^.{1,255}$`)
 )



// ValidateRoleString is used to check if the string is a valid AAS role string
func ValidateRoleString(roleString string) error {
	if !roleNameReg.MatchString(roleString) {
		return errors.New("Invalid role string provided")
	}

	return nil
}

// ValidateServiceString is used to check if the string is a valid AAS service string
func ValidateServiceString(serviceString string) error {
	if !serviceNameReg.MatchString(serviceString) {
		return errors.New("Invalid service string provided")
	}

	return nil
}

// ValidateContextString is used to check if the string is a valid AAS context string
func ValidateContextString(contextString string) error {
	if !contextReg.MatchString(contextString) {
		return errors.New("Invalid context string provided")
	}

	return nil
}

// ValidateUserNameString is used to check if the string is a valid AAS user name string
func ValidateUserNameString(userNameString string) error {
	if !aasUsernameReg.MatchString(userNameString) {
		return errors.New("Invalid user name string provided")
	}

	return nil
}

// ValidatePasswordString is used to check if the string is a valid AAS password string
func ValidatePasswordString(passwordString string) error {
	if !aasPasswordReg.MatchString(passwordString) {
		return errors.New("Invalid password string provided")
	}

	return nil
}