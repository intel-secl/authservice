// Auth Service
//
// Auth service resources are used to manage users, roles and permissions for the role(s) and manages the authentication and 
// authorization of all ISecL services. 
// Auth service uses a Bearer Token authentication method, which replaces the previous HTTP BASIC authentication.
// A bearer token will be obtained that can be used in the Authorization header for other API requests.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause 
//
//  Version: 2.2
//  Host: authservice.com:8444
//  BasePath: /aas
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey 
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package docs

import "intel/isecl/lib/common/v2/types/aas"

// UserCredInfo request payload
// swagger:parameters UserCredInfo
type UserCredInfo struct {
	// in:body
	Body aas.UserCred
}


// swagger:operation POST /token Token getJwtToken
// ---
// description: |
//   Creates a new bearer token that can be used in the Authorization header for other API 
//   requests. Bearer token Authorization is not required when requesting token for Authservice 
//   admin user. Authservice admin user bearer token should be provided in Authorization header 
//   when requesting bearer token for other users.
//
// consumes:
// - application/json
// produces:
// - text/plain
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/UserCred"
// responses:
//   '200':
//     description: Successfully created the bearer token.
//     schema:
//       type: string
//       example: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImYwY2UyNzhhMGM0OGI5NjE3YzQxNzViYmMz
//         ZWIyNThjNDEwYzI2NzUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZ
//         SI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsI
//         m5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc
//         2VyUm9sZU1hbmFnZXIifV0sImV4cCI6MTU3OTE4ODEwMSwiaWF0IjoxNTc5MTgwO
//         TAxLCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluX2FhcyJ9.dI95
//         8fYhz2RxcnXbeTgmOVTykW6en315lAOofh4kljIAiYJlCzg7EJsr5TysDynlXN1J
//         CFHxLXOv2mLwx-VCXUPRvynTuENFUxNxnj13a1SlesYWQMt8cJUUfIHuz8pFWA71
//         OIqdR6LO7z98A1HCaM6UDusskw53EpUOx2ZYm_WTxWdnI0Gp-VKMDCt7JlR497o8
//         o5xBpiuoeJDd_7fl5lfaOdkocedisAtwqhDxAsMhmlxfJ7CeR5yic1YmVN9kDwjA
//         l_IF248K12Vu7QiFsuTt5NJUqyOCWHS1igv_U67-55o5sR37xciDgPg-z1bGIdTm
//         g-GxCZQNbo5I6zr5E-_GgzsBfbIWvN_sxFXq7pN3CN7wvCfnEGXsW4coThT2PS6V
//         roDctDvds396GUcr1Ra077t8q_ETPStLcuKyAvH994uzyVIIXKZnyb9mjDdYU168
//         4G0f6M2HpZoo9DZxeQlGf4RmZVqODSW2FH78f0x0a3UTsLsV02Si0KU1GaI2
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/token
// x-sample-call-input: |
//    {
//       "username" : "admin@aas",
//       "password" : "aasAdminPass"
//    }
// x-sample-call-output: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImYwY2UyNzhhMGM0OGI5NjE3YzQxNzViYmMz
//         ZWIyNThjNDEwYzI2NzUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZ
//         SI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsI
//         m5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc
//         2VyUm9sZU1hbmFnZXIifV0sImV4cCI6MTU3OTE4ODEwMSwiaWF0IjoxNTc5MTgwO
//         TAxLCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluX2FhcyJ9.dI95
//         8fYhz2RxcnXbeTgmOVTykW6en315lAOofh4kljIAiYJlCzg7EJsr5TysDynlXN1J
//         CFHxLXOv2mLwx-VCXUPRvynTuENFUxNxnj13a1SlesYWQMt8cJUUfIHuz8pFWA71
//         OIqdR6LO7z98A1HCaM6UDusskw53EpUOx2ZYm_WTxWdnI0Gp-VKMDCt7JlR497o8
//         o5xBpiuoeJDd_7fl5lfaOdkocedisAtwqhDxAsMhmlxfJ7CeR5yic1YmVN9kDwjA
//         l_IF248K12Vu7QiFsuTt5NJUqyOCWHS1igv_U67-55o5sR37xciDgPg-z1bGIdTm
//         g-GxCZQNbo5I6zr5E-_GgzsBfbIWvN_sxFXq7pN3CN7wvCfnEGXsW4coThT2PS6V
//         roDctDvds396GUcr1Ra077t8q_ETPStLcuKyAvH994uzyVIIXKZnyb9mjDdYU168
//         4G0f6M2HpZoo9DZxeQlGf4RmZVqODSW2FH78f0x0a3UTsLsV02Si0KU1GaI2
// ---

// swagger:operation GET /noauth/jwt-certificates JwtCertificate getJwtCertificate
// ---
// description: |
//   Retrieves the list of jwt certificates.
//
// produces:
// - application/x-pem-file
// responses:
//   "200":
//     description: Successfully retrieved the list of jwt certificates.
//     schema:
//       type: string
//       example: |
//         -----BEGIN CERTIFICATE-----
//         MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
//         MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
//         AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
//         VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
//         TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
//         jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
//         rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
//         W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
//         Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
//         5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
//         bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
//         4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
//         g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
//         EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
//         MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
//         ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
//         qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
//         zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
//         i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
//         9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
//         tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
//         jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
//         3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
//         -----END CERTIFICATE-----
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/noauth/jwt-certificates
// x-sample-call-output: |
//         -----BEGIN CERTIFICATE-----
//         MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
//         MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
//         AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
//         VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
//         TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
//         jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
//         rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
//         W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
//         Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
//         5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
//         bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
//         4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
//         g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
//         EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
//         MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
//         ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
//         qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
//         zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
//         i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
//         9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
//         tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
//         jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
//         3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
//         -----END CERTIFICATE-----
// ---

// swagger:operation GET /noauth/version Version getVersion
// ---
// description: Retrieves the version of Authservice.
//
// produces:
// - text/plain
// responses:
//   "200":
//     description: Successfully retrieved the version of Authservice.
//     schema:
//       type: string
//       example: v2.2
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/noauth/version
// x-sample-call-output: v2.2
// ---


