/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	HomeDir                       = "/opt/authservice/"
	ConfigDir                     = "/etc/authservice/"
	ExecutableDir                 = "/opt/authservice/bin/"
	ExecLinkPath                  = "/usr/bin/authservice"
	RunDirPath                    = "/run/authservice"
	LogDir                        = "/var/log/authservice/"
	LogFile                       = "authservice.log"
	HTTPLogFile                   = "http.log"
	ConfigFile                    = "config.yml"
	TLSCertFile                   = "cert.pem"
	TLSKeyFile                    = "key.pem"
	TokenSignKeysAndCertDir       = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile              = TokenSignKeysAndCertDir + "jwt.key"
	TokenSignCertFile             = TokenSignKeysAndCertDir + "jwtsigncert.pem"
	TrustedJWTSigningCertsDir     = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir            = ConfigDir + "certs/trustedca/"
	PIDFile                       = "authservice.pid"
	ServiceRemoveCmd              = "systemctl disable authservice"
	HashingAlgorithm              = crypto.SHA384
	PasswordRandomLength          = 20
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
	DefaultDBRotationMaxRowCnt    = 100000
	DefaultDBRotationMaxTableCnt  = 10
	DefaultSSLCertFilePath        = ConfigDir + "aasdbcert.pem"
	ServiceName                   = "AAS"
	DefaultHttpPort               = 8444
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	DefaultAasTlsSan              = "127.0.0.1,localhost"
	DefaultAasTlsCn               = "AAS TLS Certificate"
	DefaultAasJwtCn               = "AAS JWT Signing Certificate"
)

const (
	// privileges granted: GET_ANY_HOST, DELETE_ANY_HOST, QUERY_REPORT, VERSION, CREATE_HOST
	AdminGroupName = "Administrators"

	// privileges granted: CREATE_HOST
	RegisterHostGroupName = "RegisterHosts"

	// privileges granted: GET_HOST, POST_REPORT
	HostSelfUpdateGroupName = "HostSelfUpdate"

	RoleAndUserManagerGroupName = "RoleAndUserManager"

	RoleManagerGroupName = "RoleManager"

	UserManagerGroupName = "UserManager"

	UserRoleManagerGroupName = "UserRoleManager"
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

func GetDefaultAdministratorRoles() []string {
	return []string{"RoleManager", "UserManager", "UserRoleManager"}
}
