# Auth Service Low Level Documentation

## Acronyms

|     | Description                 |
|-----|-----------------------------|
| AAS | Authentication & Authorization Service    |



# Overview

The `Auth Service` is a web service whose purpose is to authenticate a user and return has the mapping or users to roles

The `Auth Service` has following core functionalities:

## Requirements
### UserName and Password requirements

Passwords has the following constraints
 - cannot be empty - ie must at least have one character
 - maximum length of 255 characters

UserName has the following requirements
 - Format: username[@host_name[domain]]
 - [@host_name[domain]] is optional
 - username shall be minimum of 2 and maximum of 255 characters
 - username allowed characters are alphanumeric, `.`, `-`, `_` - but cannot start with `-`.
 - Domain name must meet requirements of a `host name` or `fully qualified internet host name`
 - Examples
   -  admin, admin_wls, admin@wls, admin@wls.intel.com, wls-admin@intel.com

Role - Service, Name and Context, Permissions has the following requirements
 - `Service` field contains a minimum of 1 and maxumum of 20 charecters. Allowed charecters are alphanumeric plus the special charecters `-`, `_`, `@`, `.`, `,`
 - `Name` field contains a mminimum of 1 and maxumum of 40 charecters. Allowed charecters are alphanumeric plus the special charecters `-`, `_`, `@`, `.`, `,`
 - `Service` and `Name` fields are mandatory
 - `Context` field is optional and can contain upto 512 characters. Allowed charecters are alphanumeric plus ` `, `-`, `_`, `@`, `.`, `,`,`=`,`;`,`:`,`*`
 - `Permissions` field is optional and allow upto a maximum of 512 characters. 


## User Stories
### Create, Read, Update, Delete Roles
As a role administratrator, I want to be able to manage roles so that I can create, query and delete roles.

####Acceptance Criteria
Roles Required for Operation
AAS:RoleManager or AAS:Administrator

Role Creation
1. A role cannot be created unless user has the right privilege
2. A role can be created only if the service and name fields are filled out.  A context is optional for creating a role
3. A new role shall not be created if a role that matches all fields already exists in the database
4. A user with a limited scope as an AAS RoleManager shall only be able to create roles for that particular service. For instance, a user with AAS:RoleManager:WLS can only create roles in the database that such as WLS:Administrator, WLS:User etc. He will not be able to create roles such as TDS:User or AAS:RoleManager

Role Query
1. Roles  cannot be queried unless user has the right privilege
2. Able to query the roles that exists in the database
3. Able to filter the roles retrieved by service, name and context
4. Able to query a particular role by the role id

Delete Role

1. A role cannot be delete unless user has the right privilege
2. Users with limited context/ scope can only delete roles in that service. For example someone with AAS:RoleManager:WLS may delete the role WLS:User but not TDS:User


### Create, Read, Update, Delete Users
As a user administrator, I want to be able to manage users - ie create/ query and delete users from the database.

####Acceptance Criteria
Roles Required for Operation
AAS:UserManager or AAS:Administrator

User Creation
1. A user cannot be created unless user has the right privilege
2. A user can be created only in the username and password are specified
3. A new user shall not be created if a record with the same username exists in the database


User Query
1. Need right privilege to perform query operations.
2. Able to query the users that exists in the database
3. Able to filter the the users by username
4. Able to query a particular user by the user id

Delete User

1. Need above mentioned roles in order to delete users from the database

Update User/Reset User password

1. Need above mentioned roles in order to update the users or reset his password
2. Able to change the username or reset the password. Reset password is to temporarily block user or change forgotter password

### Assign, Read, Update and Remove user roles

As a user role administrator, I want to be able to add, remove and query roles that are assigned to users

####Acceptance Criteria
Roles Required for Operation
AAS:UserRoleManager or AAS:Administrator

Create Role Association
1. Role association needs privileges
2. If administrator performing the association has restricted scope, role association can be done for that service
3. A user with a limited scope as an AAS UserRoleManager shall only be able to create user-role association for that particular service. For instance, a user with AAS:UserRoleManager:WLS can only create user-role association in the database for roles such as WLS:Administrator, WLS:User etc. He will not be able to create role-association like TDS:User or AAS:RoleManager

Query Role Association
1. Role association  cannot be queried unless user has the right privilege
2. Able to query the role association that exists in the database
3. Able to filter the role association retrieved by service, name and context
4. Able to query a particular role by the role id

Delete Role Association

1. A role association cannot be delete unless user has the right privilege
2. Users with limited context/ scope can only delete role association in that service. For example someone with AAS:UserRoleManager:WLS may delete user-role association for role WLS:User but not TDS:User


*Update will not be part of Phase 1*

### Obtain a token
As a user in the database and having password, I shall be able to obtain a JWT Token from the Authentication and Authorization service.

####Acceptance Criteria

1. If invalid credentials are supplied, the server and unauthorized error code
2. The JWT token shall contain the roles that the user had


The user can choose to restrict the token by the following attributes - *not in scope for Phase 1*
    1. service
    2. Role
    3. time (so instance, I only want a token that is valid for 5 mins to carry out a specific task )

### AAS uses a TLS Certificate that is issued by know entity
As a user of the Authentication service, I want to make sure that I am indeed communicating with an AAS that I trust.

#### Acceptance Criteria

1. The Certificate presented by the Http server of AAS shall be issued by an authority that I trust
2. In intial implementation, TLS certificate used by AAS http server is issued by CMS
3. The TLS certificate presented by AAS shall meet the criteria for domain name verification. This means that the host part of the AAS URL used for communication shall be part of the SAN List


### AAS shall only accept tokens that signed by Certificate Authrities that it trusts
As a user, I need to make sure that AAS implements the right security practices in order to have the confidence in the service that I am using

#### Acceptance Criteria

1. AAS shall only accept tokens from trusted entities to validate clients that are performing operations on itself
2. The JWT signing certificates that are trusted by AAS shall be issued by Certificate Authorities that it trusts
3. Currently, the only root CA that it trusts is the one from CMS


### Install AAS
A user should be able to install the AAS service. As part of the installation process, the following items should be accomplished
  1. Set up a database
  2. Install root certificate of CMS
  3. Request TLS Certificate from CMS, store it and configure https with TLS certificate a
  4. Request JWT signing certificate from CMS, store it - to be used for token signing
  5. Specify an admin user who will have the roles to perform role and user management
  9. A daemon is configured to run the AAS service and started

#### Integration with CMS
AAS uses CMS as the Central Authority of trust. Below is a list of items that the AAS needs the CMS for
  1. The certificate used by the AAS http server shall be issued by the CMS. Since the CMS root certificate is the root of trust for all clients in the ecosystem, need to get a TLS certificate that is signed by CMS.
  The SAN List of certificate shall contain IP addresses and hostnames that clients shall use to connect to AAS. This enables clients to perform full Certificate verification
  2. Obtain the JWT certificate. AAS creates tokens that contains authorizatoin information. Again as the CMS is the root of trust and all clients trust the CMS root CA, need a certificate JWT certificate that is signed by CMS. Services that are verifying the token can make sure that the certificate used to sign the token is from an authority that it trusts
  3. Download root CA. AAS might decide to accept JWT from other services or peer AAS for authorizing its own Rest end points. In this case, need to verify that the JWT cert is issued from a trusted authority.


## API Endpoints

## Token related

### POST `/aas/token`
Retrieve a token with supplied user credentials. Return a map of roles assiociated with the user as well optional scope that contains contextual information pertaining to the user-role mapping.

- Authorization: NONE (username and password in POST body)
- Content-Type: `application/json`
- Accept: `application/jwt`

```json
{
    "username": "user name",
    "password": "password of user"
}
```

The following fileds are optional and will not be part of Phase 1 implementation

```json
{
  "service" : "restrict roles to just this service",
  "role" : "just this role when desired role is known",
  "validity" : "time the token is valid for",
  "include_username" : "include the username as well in the token(off by default)"
}
```

These optional fields are used to restrict how long and where the token may be used.

Example Response:

eyJhbGciOiJFUzM4NCIsImtpZCI6ImZjOGU1Y2UwMmM4NTBlMjc3ZWRmNWEwOTc3NGM2Y2M4ODJlYzg0NmIiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0aWZpY2F0ZVJlcXVlc3RvciIsImNvbnRleHQiOiJDTj13bHMuaXNlY2wuaW50ZWwuY29tIn0seyJzZXJ2aWNlIjoiVERTIiwibmFtZSI6Ikhvc3RVcGRhdGVyIiwiY29udGV4dCI6Ikhvc3RBIn0seyJzZXJ2aWNlIjoiV0xTIiwibmFtZSI6IkNlcnRpZmljYXRlUmVxdWVzdG9yIiwiY29udGV4dCI6IkNOPXdscy5pc2VjbC5pbnRlbC5jb20ifV0sImV4cCI6MTU2MTY4MDE4NywiaWF0IjoxNTYxNTkzNzg3LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InZpbmlsIn0.akv_xcSciKs2wR_dRHG-IOU0mdo9S2ATZ2tg0-kr-Ph6W2HS7qk0sVZwUTFQgT6uPY1UhcXo2QYoziSToT-hnZBNnu8a4MI2dXeUSGOISzfw6NIAWlCDbC_TMJfF1IuX

The above token correspond to the following

HEADER:ALGORITHM & TOKEN TYPE
```json
{
  "alg": "ES384",
  "kid": "fc8e5ce02c850e277edf5a09774c6cc882ec846b",
  "typ": "JWT"
}
```
PAYLOAD:DATA
```json
{
  "roles": [
    {
      "service": "CMS",
      "name": "CertificateRequestor",
      "context": "CN=wls.isecl.intel.com"
    },
    {
      "service": "TDS",
      "name": "HostUpdater",
      "context": "HostA"
    },
    {
      "service": "WLS",
      "name": "CertificateRequestor",
      "context": "CN=wls.isecl.intel.com"
    }
  ],
  "exp": 1561680187,
  "iat": 1561593787,
  "iss": "AAS JWT Issuer",
  "sub": "vinil"
}
```
VERIFY SIGNATURE
```golang
ECDSASHA384(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload))
 ```

## User Management
### POST `/aas/users`

Create a user in AAS

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"users:create:*"`

```json
{
    "username": "user[@domain]",
    "password": "password",
}
```
Example Response:
```json
{
    "user_id" : "7c8f2399-e1b3-4e91-8b25-1d7703c91c79",
    "username": "wls_admin"
}
```

### GET `/aas/users`

Query Users

- Authorization: `Bearer Token`
- Permissions: `"users:search:*"`

Example Response:
```json
[
    {
        "user_id": "123e4567-e89b-12d3-a456-426655440000",
        "username": "system_user@wls",
    },
    {
        "id": "223e4567-e89b-12d3-a456-426655440000",
        "username": "admin",
    },
]
```
Available Query parameters:

- name=(username)

### GET `/aas/users/{id}`

Get a single user by ID

- Authorization: `Bearer Token`
- Permissions: `"users:retrieve:*"`

Retrieve information regarding a specific user
- `GET /aas/users/123e4567-e89b-12d3-a456-426655440000`

Example Response:

```json
{
    "user_id": "223e4567-e89b-12d3-a456-426655440000",
    "username": "admin"
},
```



### DELETE `/aas/users/{user_id}`

- Authorization: `Bearer Token`
- Permissions: `"users:delete:*"`

Response: success/failure

deletes user from database with specific user id. Deleting a record using this method is a 2-step process as we need to first obtain the user uuid using the `GET` method.

### PATCH `/aas/users/{userid}`

used to update a user (change username) or reset password
- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"users:store:*"`

```json
{
    "username": "new_user_name",
    "password": "reset_or_new_password"
}
```
Response: success/failure

Out of these, either of these fields are optional. Record associated with the `{user_id}` will be updated. New supplied username shall not conflict with an existing user.

`password` if provided will be the new password for the user. There is no state such as reset. It is upto the user to change the password using `changepassword` api

### PATCH `/aas/users/changepassword`

Used by user to change the password using current password.

- Authorization: NONE (username and current password is in PATCH body)
- Content-Type: `application/json`

```json
{
    "username": "username",
    "old_password": "old_password",
    "new_password": "new_password",
    "password_confirm": "new_password"
}
```
`username` and `old_password` is used to authenticate the user. `new_password` and `password_confirm` represents the new passwords and they should match

## Role Management
### POST `/aas/roles`

Create a role in AAS. In the below, the context is optional. Usage of context depends on the microservice.

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"roles:create:*"`

```json
{
    "service": "CMS",
    "name": "CertificateRequestor",
    "context": "CN=wls.isecl.intel.com"
}
```
Example Response:
```json
{
    "role_id":"e4faf9b0-606d-4a50-a3b8-bb7fbd1d6e2e",
    "service":"CMS",
    "name":"CertificateRequestor",
    "context":"CN=wls.isecl.intel.com"
}
```
### GET `/aas/roles`

Query Users

- Authorization: `Bearer Token`
- Permissions: `"roles:search:*"`

Example Response:
```json
[
    {
        "role_id": "7faf7c0c-3701-4844-aeb2-df81449fab0a",
        "service": "AAS",
        "name": "Administrators"
    },
    {
        "role_id": "e66ffa0e-1ffa-475c-a6fc-c8f12487b6c0",
        "service": "TDS",
        "name": "RegisterHosts"
    },
    {
        "role_id": "1c17bd44-9797-428d-9eb2-747ea786f461",
        "service": "CMS",
        "name": "CertificateRequestor",
        "context": "CN=wls.isecl.intel.com"
    }
]
```
Available Query parameters:

- service=(service name - only get roles where for this queried service)
- name=(role name)
- context=(only looking for roles matching certain context)
- contextContains=(substring to match context) - if both context and contextContains are present, context is used and cotextContains is ignored
- allContexts=<true|false> - false means that record(s) returned would be the ones where the context field is empty

### GET `/aas/roles/{id}`

Get a single role by ID

- Authorization: `Bearer Token`
- Permissions: `"roles:retrieve:*"`

Retrieve information regarding a specific role
- `GET /aas/roles/123e4567-e89b-12d3-a456-426655440000`

Example Response:
```json
    {
        "role_id": "1c17bd44-9797-428d-9eb2-747ea786f461",
        "service": "CMS",
        "name": "CertificateRequestor",
        "context": "CN=wls.isecl.intel.com"
    }
```

### DELETE `/aas/roles/{id}`

DELETE a role in AAS

- Authorization: `Bearer Token`
- Permissions: `"roles:delete:*"`

## User Role Management
### POST /aas/users/{userid}/roles

Assign a role to the user. User roles association is only allowed using ids. You have to call `GET /aas/roles` to determine th ids

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"user_roles:create:*"`

```json
    {
        "role_ids": ["uuid_1", "uuid_2", "uuid_3"]
    }
```
You can assign a single role by having a single uuid in the array as below
```json
    {
        "role_ids": ["uuid_1"]
    }
```

### DELETE /aas/users/{userid}/roles/{role_id}

Delete a role association with the user. Right now, there are no bulk operation to delete multiple role associations

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"user_roles:delete:*"`

### GET aas/users/{userid}/roles/{role_id}

Get a particular role associated with the user.

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"user_roles:retrieve:*"`

Example Response:
```json
{
    "role_id": "7faf7c0c-3701-4844-aeb2-df81449fab0a",
    "service": "AAS",
    "name": "Administrator"
}
```
### GET aas/users/{userid}/roles/

Get all roles that are associated with the user.

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"user_roles:search:*"`

Example Response:
```json
[
    {
        "role_id": "7faf7c0c-3701-4844-aeb2-df81449fab0a",
        "service": "AAS",
        "name": "Administrators"
    },
    {
        "role_id": "e66ffa0e-1ffa-475c-a6fc-c8f12487b6c0",
        "service": "TDS",
        "name": "RegisterHosts"
    },
    {
        "role_id": "1c17bd44-9797-428d-9eb2-747ea786f461",
        "service": "CMS",
        "name": "CertificateRequestor",
        "context": "CN=wls.isecl.intel.com"
    }
]
```

### GET aas/users/{userid}/permissions/

Get all permissions that are associated with the user.

- Authorization: `Bearer Token`
- Content-Type: `application/json`
- Permissions: `"user_roles:search:*"`

Example Response:
```json
[{
	"service": "AAS",
	"rules": ["*:*:*", "roles:create:*", "roles:delete:*", "roles:retrieve:*", "roles:search:*"]
}]
```
Available Query parameters:

- service=(service name - only get roles where for this queried service)
- name=(role name)
- context=(only looking for roles matching certain context)
- contextContains=(substring to match context) - if both context and contextContains are present, context is used and cotextContains is ignored
- allContexts=<true|false> - false means that record(s) returned would be the ones where the context field is empty

### GET aas/noauth/jwt-certificates

Get the JWT Signing Certificate which may be used to verify the token that has been signed by AAS

- Authorization: `none`

Example Response:

```text
-----BEGIN CERTIFICATE-----
MIIEBzCCAm+gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
.....
xGp0ClD5tg5oTSPLVYZrye/dY1wvbMmSYxU7zsEwzwqba1Cl3mSNe8YURvOQXpl/
jYHfg7o1fmBEx9IJKFp43ezxyV5Cw/gvQQLR
-----END CERTIFICATE-----
```
### GET aas/noauth/version

Get version of AAS
- Authorization: `none`

Example Response:

```text
v0.0.0-4563a0a
```


## Database Schema

### roles
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
 id         | uuid                     |           | not null |
 created_at | timestamp with time zone |           |          |
 updated_at | timestamp with time zone |           |          |
 service    | text                     |           |          |
 name       | text                     |           | not null |
 context    | text                     |           |          |
Indexes:
    "roles_pkey" PRIMARY KEY, btree (id)


Indexes:
    "roles_pkey" PRIMARY KEY, btree (id)

### users
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
 id            | uuid                     |           | not null |
 created_at    | timestamp with time zone |           |          |
 updated_at    | timestamp with time zone |           |          |
 deleted_at    | timestamp with time zone |           |          |
 name          | text                     |           |          |
 password_hash | bytea                    |           |          |
 password_salt | bytea                    |           |          |
 password_cost | integer                  |           |          |
Indexes:
    "users_pkey" PRIMARY KEY, btree (id)



Indexes:
    "users_pkey" PRIMARY KEY, btree (id)

### user_roles
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
 user_id | uuid |           | not null |
 role_id | uuid |           | not null |
Indexes:
    "user_roles_pkey" PRIMARY KEY, btree (user_id, role_id)

Indexes:
    "user_roles_pkey" PRIMARY KEY, btree (user_id, role_id)


## Logging

Logging features of AAS are not fully developed. This shall be addressed in a subsequent release. For now, most of the logs pertaining to AAS service/ daemon are logged in the journalctl. You may view the logs by using

```shell
journalctl -u authservice
```

# Auth Service Installaton

There are two modes of installation:

1. Bare Metal
2. Container

## Bare Metal Installation

The daemon will create and use the following files on the OS:

1. /var/log/authservice/authservice.log
2. /var/log/authservice/http.log
3. /etc/authservice/config.yaml (Configuration)
4. /usr/\*/bin/authservice (executable binary)
5. /etc/authservice/tls.key (TLS key)
6. /etc/authservice/tls-cert.pem (TLS cert)

## Container Installation - Not currently tested/ supported

Since `AAS` is a standalone web service, container deployment is trivial.

All necessary setup options should be readable from environment variables, so the container can be spun up by only passing environment variables

# TLS Configuration -

Currently, there are no requirements for  `AAS` for clients to present certificates. Authentication to clients uses basic authentication.

`AAS` server certificate shall be stored in a the following location `/etc/authservice/tls-cert.pem`. During AAS installation time, the AAS has to request a certificate from the CMS. In order to do this, the installation needs a token that is signed by CMS that has privileges to request an AAS TLS certificate.

## Root Certificates -

The root certificates that are used by `AAS` are stored in `/etc/authservice/certs/trustedca`. During setup, `root CA` is downloaded from `CMS` and stored in this directory. If using certificates from a 3rd party CA, root certificates can be stored in this directory.

# AAS Features
## Authentication and Authorization

### Authentication Defender

The authenticaiton defender is a designed to thwart disctionary based attacks by locking the account for a specified time. If there are x number of attempts in y time, the account would be locked out for a period of z time. The current default is 5 attempts in 5 minutes and you are locked out for 15 minutes. These may be configured in the config file and is loaded when the daemon restarts.

## Setup and Runtime Configuration

Setup relies on environment variables to configure the Authentication Service. The installer looks for a file called `authservice.env` in the home directory of the user running the installation. This file can list the needed environment variables that will be exported during installation. You may alternatively export these environment variables using `export` in the shell environment.

Some of configuration variable are only needed during setup. Others are used during runtime. All the configuration entries needed during runtime are stored in configuration file `/etc/authservice/config.yml`

### Environment Variables
```shell
# database connection related, all mandatory
AAS_DB_HOSTNAME=<database_hostname_or_ip> 
AAS_DB_PORT=<database_port>
AAS_DB_USERNAME=<db_user>
AAS_DB_PASSWORD=<db_user_password>
AAS_DB_NAME=<name_of_db_in_db_server>

# database TLS connection related. Please see details in the SSL/TLS connection to database section
#optional - if not specified, no certificate verification will be performed
AAS_DB_SSLMODE=verify_ca|require
#optional
AAS_DB_SSLCERTSRC=<path_to_cert_file_to_be_copied>
#optional
AAS_DB_SSLCERT=<path_to_cert_file_on_system>

# Root CA, TLS Certificate and JWT Certificate related
# mandatory - URL of CMS server
CMS_BASE_URL=https://<ip_address/host_name_ofcms>/cms/v1/
# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39...
# optional - TLS Certificate Subject name (default will be used)
COMMON_NAME="AAS TLS Certificate"
# mandatory - otherwise, it will be only localhost and 127.0.0.1
SAN_LIST=comma_seperated_list_of_ip_addresses_and_host_names
#optional -  Subject/ Common Name for JWT signing certificate obtained from CMS
AAS_JWT_CERT_SUBJECT="AAS JWT certificate"
#mandatatory bearer token in JWT form obtained from CMS for retrieving TLS and JWT signing cert
BEARER_TOKEN=eyJhbGciOiJFUzM4NCIs....

# Options for AAS issues JWT token
# option duration in minutes how long the JWT token is valid - default is 120 (2 hours
AAS_JWT_TOKEN_DURATION_MINS=120 )


# Administrator related
# mandatory - name of administrator user
AAS_ADMIN_USERNAME=<admin_user_name>
# mandatory - password of administrator user
AAS_ADMIN_PASSWORD=<password>

# Miscellaneous
# optional - if not supplied, it will be set to 'warning'
LOG_LEVEL=critical|error|warning|info|debug|trace
# optional - if not supplied, it will be set to 300
AAS_LOG_MAX_LENGTH=300
# optional - if not supplied, it will be set to false
AAS_ENABLE_CONSOLE_LOG=true
```

### Configuraiton variables
The configuration variables used during runtime is stored in `/etc/authservice/config.yml`. Most of these are self explanatory - rest of them are documented. Changing any of these would require a restart of the service/daemon

```yaml
# port number of authentication http server
port: 8444
cmstlscertdigest: 3c95457d5adcb19c223d538d01c39b99df2eb0e07a2a52466531368e96473ab3497dcc02c378a21db0de37da128584d1
postgres:
  dbname: pgdb
  username: dbuser
  password: test
  hostname: localhost
  port: 5432
  sslmode: verify-ca
  sslcert: /etc/authservice/aasdbcert.pem
loglevel: info

# configuration of authentication defender. A user is locked our for 'lockdurationmins' if 'maxattempts' of unsuccessful login is attempted within a span of 'intervalmins'
authdefender:
  maxattempts: 5
  intervalmins: 5
  lockoutdurationmins: 15
# JWT token related options. The 'includekid' is no longer optional. tokendurationmins controls validity of token in minutes
token:
  includekid: true
  tokendurationmins: 2880
cmsbaseurl: https://cms.isecl.intel.com:8445/cms/v1/
subject:
  tlscertcommonname: AAS TLS Certificate
  jwtcertcommonname: AAS JWT Signing Certificate
  organization: INTEL
  country: US
  province: SF
  locality: SC
```

# Command Line Operations

## Setup

Available setup tasks:
- database
- admin
- jwt
- cms
- all
- download_ca_cert
- download_cert



### Setup - Database

Sets up the database
```shell
> authservice setup database [-force] --db-host=postgres.com --db-port=5432 --db-user=admin --db-pass=password --db-name=aas_db
```
`--force` overwrite the existing values

Environment variables
```shell
# mandatory - alternatively use --db-host argument
AAS_DB_HOSTNAME=<database_hostname_or_ip>

# mandatory - alternatively use --db-port argument
AAS_DB_PORT=<database_port>

# mandatory - alternatively use --db-user argument
AAS_DB_USERNAME=<db_user>

# mandatory - alternatively use --db-pass argument
AAS_DB_PASSWORD=<db_user_password>

# mandatory - alternatively use --db-name argument
AAS_DB_NAME=<name_of_db_in_db_server>
```


##### SSL/ TLS Connection to database
Communication with database shall by default be over a secure channel even if the database is on the same server as `AAS`. There are several parameters that may be used for this. The following provides an explanation of how this may be used
```shell
# no database ssl config parameters specified in env file
# we will use "sslmode=require". No database tls/ssl certification verification is performed
# config.yml will have values "sslmode: require" and "sslcert:"

# This section describes various combination of database ssl/tls parameters
# sample env file configuration for localhost
AAS_DB_SSLMODE=verfy-ca
AAS_DB_SSLCERTSRC=/usr/local/pgsql/data/server.crt
# Here since AAS_DB_SSLCERT is empty, the file at /usr/local/pgsql/data/server.crt will be copied to /etc/authservice/aasdbcert.pem
# config.yml will have value "sslcert: /etc/authservice/aasdbcert.pem" and "sslmode: verify-ca"

# env config when you do not want copy the file - rather just specify the location of the database cert
AAS_DB_SSLMODE=verfy-ca
AAS_DB_SSLCERT=/usr/local/pgsql/data/server.crt
# in this case, AAS_DB_SSLCERTSRC is not set, so we will keep the file at /usr/local/pgsql/data/server.crt and it will be used
# here - it is expected that /usr/local/pgsql/data/server.crt exists and can be read by the aas user
# config.yml will have value "sslcert: /usr/local/pgsql/data/server.crt" and "sslmode: verify-ca"

# source and destination specified
AAS_DB_SSLMODE=verfy-ca
AAS_DB_SSLCERTSRC=/usr/local/pgsql/data/server.crt
AAS_DB_SSLCERT=/root/server.crt
# file will be copied from /usr/local/pgsql/data/server.crt to /root/server.crt
# config.yml will have the value "sslcert: /root/server.crt" and "sslmode: verify-ca"

# Remote Database installation
AAS_DB_SSLMODE=verfy-ca
# copy over the file from the remote database and stick it in your home folder
AAS_DB_SSLCERTSRC=/root/server.crt
# since AAS_DB_SSLCERT is empty, the file at /root/server.crt will be copied to /etc/authservice/aasdbcert.pem
# config.yml will have value "sslcert: /etc/authservice/aasdbcert.pem" and "sslmode: verify-ca"
```

### Setup - HTTP Server
Configuration parameters for http server
```shell
> authservice setup server --port=8443
```
Environment variables
```shell
# optional (8444 will be default) - use this env variable or --port argument
AAS_PORT=444 # port that the http server listens on

# mandatory - URL of CMS server
CMS_BASE_URL=https://<ip_address/host_name_ofcms>/cms/v1/

# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39...
```
### Setup - Download Root Certificate
Downloads the Root CA from CMS.

```shell
> authservice setup download_ca_cert [--force]
```
`--force` overwrites any existing files and download a new certificate from CMS

 You will need the following environment variable to download the root certificate

```shell
# mandatory - no commmand line arguments currently available in lieu of this
CMS_BASE_URL=https://<ip_address/host_name_ofcms>/cms/v1/ #URL of CMS server

# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39... 

```



### Setup - TLS
Downloads the TLS certificate for the Authentication Service from the CMS. Currently most of the arguments for this setup function is only supported through exported environment variables. The following are the supported environment variable applicable for downloading the certificate

```shell
> authservice setup download_cert [--force] [--host_names=intel.com,10.1.168.2]
```
`--force` overwrites any existing files and download a new certificate from CMS

Environment variables

```shell
# mandatory - no commmand line arguments currently available in lieu of this
CMS_BASE_URL=https://<ip_address/host_name_ofcms>/cms/v1/ #URL of CMS server

# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39... 

# optional (default will be used)
COMMON_NAME="AAS TLS Certificate" # Common name in the TLS certificate of AAS. Needs to match attribute in JWT token

# mandatory - otherwise, it will be only localhost and 127.0.0.1
SAN_LIST=comma_seperated_list_of_ip_addresses_and_host_names # All IP addresses and host names that AAS may be reached by

```




### Setup - jwt

```shell
> authservice setup jwt [--subj=<"AAS JWT Certificate">] [--token=bearer_token_from_CMS] [--cms-url=<base_url_of_CMS>] [--valid-mins=<jwt_token_validity_in_mins>] [--keyid=<true|false>]

```

Environment variables

```shell

# optional - alternatively use --subj argument (if not supplied default will be used)
AAS_JWT_CERT_SUBJECT="AAS JWT certificate" #optional argument if you want override default

# mandatory - alternatively use --cms-url argument
CMS_BASE_URL=https://x.x.x.x:8445/cms/v1/ # url of the Certificate Management Server

# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39... 

# mandatory - alternatively use --token argument
BEARER_TOKEN=eyJhbGciOiJFUzM4NCIs....  #bearer token in JWT form obtained from CMS

# optional - alternatively use --valid-mins argument (if not supplied default will be used)
AAS_JWT_TOKEN_DURATION_MINS=2880 # duration in minutes how long the JWT token is valid for (2880=48 hours)


```

### Setup - Admin
Set up an administrator user that has the predefined roles for AAS.

```shell
> authservice setup admin --user=admin --pass=password
```

Environment variables

```shell
# mandatory - alternatively use --cms-url argument
CMS_BASE_URL=https://x.x.x.x:8445/cms/v1/ # url of the Certificate Management Server

# mandatory - this is used to verify the CMS before the root-CA is downloaded.
CMS_TLS_CERT_SHA384=3c95457d5adcb19c223d538d01c39... 

# mandatory - --user argument may be used instead
AAS_ADMIN_USERNAME=<admin_user_name>

# mandatory --pass argument may be used instead
AAS_ADMIN_PASSWORD=<password>
```

This task can be used to create administrator user. The same may be used to create additional users or change the pass work of an existing administrative user



## Start/Stop

```shell
> authservice start
  Auth Service started
> authservice stop
  Auth Service stopped
> authservice status
  Auth Service status

```

## Uninstall

```shell
> authservice uninstall [--keep-config]
  Auth Service uninstalled
```
Uninstalls Auth Service, with optional flag to keep configuration

## Help

```shell
> authservice (help|-h|-help)
  Usage: authservice <command> <flags>
    Commands:
    - setup
    - help
    - start
    - stop
    - status
    - uninstall
    - version
```

## Version

```shell
> authservice version
    Auth Service v1.0.0 build 9cf83e2
```


# Postgres Database Installation Script
##### *Warning: Do not use the script on a server that already has a postgres database installed. It will remove your current database working directory*  
A script has been provided that may be used to install a Postgres database. Customers may choose to install their own postgres database installation and configuration. The script is merely provided for ease of installation.

This script may be used for installing the database on the same server as the service or the database may be installed on a remote server. The script does the following
 - A user is created with minimal privileges to the database used by the service. The goal is that the user credential supplied for the service to connect to the database only has minimum privileges to perform database operations that the service needs
 - Database may be installed on the same server as the service or a remote server
 - Default setting of the script uses TLS/ SSL to connect the database. An RSA Keypair and self signed certificate is generated by the script and configured as the TLS/SSL certificate for the database. You may configure your own certificates instead of this. Please refer to postgres documentation on how to configure certificates for the database

#### Environment file for configuring the database

You may use an enviroment variable file (`iseclpgdb.env`) file for configuring the remote database installation and it needs to be located in the same directory as the database installation script. This is optional for a installing the database on the same machine as the service as it will use default value in the script (you however have to specify the password as an argument)

```shell
# Sample env file with explanation of parameters
ISECL_PGDB_IP_INTERFACES=localhost    # for localhost or 0.0.0.0 for listening on all IP addresses
                                      # corresponds to listen_addresses in postgres documentation

ISECL_PGDB_PORT=5432                  # the listening port of the database
ISECL_PGDB_DBNAME=pgdb                # name of the database for the service, eg aas-db for AAS database
ISECL_PGDB_USERNAME=dbuser            # user that can connect to the database from the service
ISECL_PGDB_USERPASSWORD=strongpass    # password for database user

ISECL_PGDB_SERVICEHOST=192.168.1.1/32 # these are hosts that are allowed to connect to the database
ISECL_PGDB_ALLOW_NONSSL=false         # for debugging primarily. Set to true if you want to allow non SSL connection to database from remote
ISECL_PGDB_CERT_VALIDITY_DAYS=3652    # validitiy of certificate. Set to 10 years here (2X 366 day leap years)

ISECL_PGDB_CERTSUBJECT="/CN=ISecl Self Sign Cert"  # this is the common name in the certificate. Check Openssl documention for various field for "subject"
```

Example `iseclpgdb.env` file for database installed on a remote server.

```shell
ISECL_PGDB_IP_INTERFACES=0.0.0.0      # listens on all network adapters
ISECL_PGDB_DBNAME=aasdb               # name of the database for the service, eg aas-db for AAS database
ISECL_PGDB_USERNAME=runner            # user that can connect to the database from the service
ISECL_PGDB_USERPASSWORD=strongtestpw  # password for database user

ISECL_PGDB_SERVICEHOST=192.168.1.50/32
#ISECL_PGDB_SERVICEHOST=192.168.1.0/24  # any machine in the 19.168.1.x network can connect to the database
```
#### Using the database installation Script
Have  the `iseclpgdb.env` file in the same directory as the `install_pgdb.sh` file. If you are using default value in the `install_pgdb.sh` script, you may run the script by specifying the password
```shell
$./install_pgdb.sh [database_password]
```
