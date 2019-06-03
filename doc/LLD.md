# Auth Service Low Level Documentation

## Acronyms

|     | Description                 |
|-----|-----------------------------|
| AAS | Authentication & Authorization Service    |



# Overview

The `Auth Service` is a web service whose purpose is to authenticate a user and return has the mapping or users to roles

The `Auth Service` has following core functionalities:



# API Endpoints

## Token related

### POST `/aas/user/token`
Retrieve a token based on authorization

- Authorization: `HTTP Basic Authentication`
- Content-Type: `application/json`
- Accept: `application/jwt`

```json
{
  "role_domain" : "restrict roles to just this domain",
  "role" : "just this role when desired role is known",
  "validity" : "time the token is valid for",
  "include_username" : "include the username as well in the token(off by default)"
}
```

The above are all optional. This is used to restrict token to limit its purpose

Example Response:
```
eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6W3siZG9tYWluIjoiQ01TIiwibmFtZSI6IkNlcnRpZmljYXRlUmVxdWVzdGVyIiwic2NvcGUiOiJDTjphYXMuaXNlY2wuaW50ZWwuY29tIn0seyJkb21haW4iOiJURFMiLCJuYW1lIjoiSG9zdFVwZGF0ZXIiLCJzY29wZSI6Ikhvc3RBIn0seyJkb21haW4iOiJXTFMiLCJuYW1lIjoiQWRtaW5pc3RyYXRvciJ9XSwiZXhwIjoxNTU5NjYzMjcwLCJpYXQiOjE1NTk1NzY4NzAsImlzcyI6IlRlc3QgSXNzdWVyIiwic3ViIjoiVmluaWwncyBKV1QifQ.XC40YN8arek7z_8WrRF5ph-0QkI6aa-ea_W9tL8jSDp1AtxLqTOwyb_6eCXBBTYqBdWC2G1RxRHf19LaLBZ053HlyOeUf3295F_Kyp8Rz0eF2aOlKA4DejX84iWqnkd5
```

The above token correspond to the following

HEADER:ALGORITHM & TOKEN TYPE
```json
{
  "alg": "ES384",
  "typ": "JWT"
}
```
PAYLOAD:DATA
```json
{
  "roles": [
    {
      "domain": "CMS",
      "name": "CertificateRequester",
      "scope": "CN:aas.isecl.intel.com"
    },
    {
      "domain": "TDS",
      "name": "HostUpdater",
      "scope": "HostA"
    },
    {
      "domain": "WLS",
      "name": "Administrator"
    }
  ],
  "exp": 1559663270,
  "iat": 1559576870,
  "iss": "Test Issuer",
  "sub": "Vinil's JWT"
}
```
VERIFY SIGNATURE
```golang
ECDSASHA384(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  base64UrlEncode(signature)
```

## User Management
### POST `/aas/users`

Create a user in AAS

- Authorization: `HTTP Basic Authentication`
- Content-Type: `application/json`

```json
{
    "id": "user[@domain]",
    "password": "password",
}
```
Example Response:
```json
{
    "user_id" : "user_uuid"
}
```

### GET `/aas/users`

Query Users

- Authorization: `HTTP Basic Authentication`


Example Response:
```json
[
    {
        "user_id": "123e4567-e89b-12d3-a456-426655440000",
        "user_name": "system_user@wls",
    },
    {
        "id": "223e4567-e89b-12d3-a456-426655440000",
        "user_name": "admin",
    },
]
```
Available Query parameters:

- userName=(user_name)

### GET `/aas/users/{id-uuidv4}`

Get a single user by ID

- Authorization: `HTTP Basic Authentication`

Retrieve information regarding a specific user
- `GET /aas/users/123e4567-e89b-12d3-a456-426655440000`

Example Response:

```json
{
    "id": "223e4567-e89b-12d3-a456-426655440000",
    "user_name": "admin",
},
```



### DELETE `/aas/users/{user_id}`

- Authorization: `HTTP Basic Authentication`

Response: success/failure

deletes user from database with specific user id. Deleting a record using this method is a 2-step process as we need to first obtain the user uuid using the `GET` method.


### DELETE `/aas/users?username=myname@intel.com`

- Authorization: `HTTP Basic Authentication`

Response: success/failure

Not sure if we should have this interface ??

### POST `/aas/users/{userid}/change_password`
(not available in intial version)

used to change password for the user if they know the existing password.
Can this be used for an admin to change password for someone else?

- Authorization: `HTTP Basic Authentication`
- Content-Type: `application/json`

```json
{
    "password" : "new_password"
}
```

Response : success/ failure

## Role Management
### POST `/aas/roles`

Create a role in AAS

- Authorization: `HTTP Basic Authentication`
- Content-Type: `application/json`

```json
{
    "role_domain" : "can be used to identify microservice - example TDS|WLS",
    "name": "role_name",
    "role_scope": "used and defined by microservice based on its needs"
}
```
Example Response:
```json
{
    "role_id" : "role_uuid"
}
```
### GET `/aas/roles`

Query Users

- Authorization: `HTTP Basic Authentication`


Example Response:
```json
[
    {
        "role_id": "123e4567-e89b-12d3-a456-426655440000",
        "role_domain" : "WLS",
        "name": "Administrator",
        "role_scope": ""    
    },
    {
        "id": "223e4567-e89b-12d3-a456-426655440000",
        "role_domain" : "AAS",
        "name": "RoleManager",
        "role_scope": "TDS"    
    },
]
```
Available Query parameters:

- roleDomain=(role_domain)
- roleName=(role_name)

### GET `/aas/roles/{id-uuidv4}`

Get a single role by ID

- Authorization: `HTTP Basic Authentication`

Retrieve information regarding a specific role
- `GET /aas/roles/123e4567-e89b-12d3-a456-426655440000`

Example Response:

```json
{
    "role_id": "123e4567-e89b-12d3-a456-426655440000",
    "role_domain" : "WLS",
    "name" : "Administrators",
    "role_scope": "",
}
```

### DELETE `/aas/roles/{id}`

DELETE a role in AAS

- Authorization: `HTTP Basic Authentication`

## User Role Management
### POST /api/users/{userid}/roles

Assign a role to the user

- Authorization: `HTTP Basic Authentication`
- Content-Type: `application/json`

```json
{
    "user_id" : "user_uuid",
    "role_id": "role_uuid",
    "validity": "4h"
}
```
## Database Schema

### roles
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
| id         | uuid                     |           | not null |
| created_at | timestamp with time zone |           |          |
| updated_at | timestamp with time zone |           |          |
| name       | text                     |           | not null |
| domain     | text                     |           |          |

### scope
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
| id         | uuid                     |           | not null |
| created_at | timestamp with time zone |           |          |
| updated_at | timestamp with time zone |           |          |
| scope      | text                     |           | not null |





Indexes:
    "roles_pkey" PRIMARY KEY, btree (id)

### users
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
| id            | uuid                     |           | not null |
| created_at    | timestamp with time zone |           |          |
| updated_at    | timestamp with time zone |           |          |
| deleted_at    | timestamp with time zone |           |          |
| name          | text                     |           |          |
| password_hash | bytea                    |           |          |


Indexes:
    "users_pkey" PRIMARY KEY, btree (id)

### user_roles
|   Column   |           Type           | Collation | Nullable |
|------------|--------------------------|-----------|----------|
| user_id  | uuid |           | not null |
| role_id  | uuid |           | not null |
| scope_id | uuid |           |  |






Indexes:
    "user_roles_pkey" PRIMARY KEY, btree (user_id, role_id)

## User Stories
### Create Roles
As someone with appropriate privileges, a user need the ability to create roles. The roles may have attributes such as domain/ tenant. This can be useful in clarifying where the role is applicable. 

### Create Roles with Scope 
This provides the ability for the role to be restricted by certain criteria. For instance, a CMS:CertificateRequestor role can have a scope "CN:aas.isecl.intel.com". This means that CMS may use this information to match the CSR request. 


### Create User
As an administrator, I want to create roles. The roles may have attributes such as domain/ tenant. This can be useful in clarifying where the role is applicable. 

### Assign User Role
A user can be assigned a role by someone with the right privilege. In addition, the privilege that the user has may be restricted to a certain scope. 

### Obtain a token 
A user can obtain a token with credentials (user name as password). The returned token will contain roles and scope. 
The user can choose to restrict the token by the following attributes
    1. Domain
    2. Role 
    3. time (so instance, I only want a token that is valid for 5 mins to carry out a specific task )

### Create a Role/ Permission with a limited time.
As a user with appropriate privileges, a user can create a role or a permission/ scope that is valid for a limited time. The goal of this is to provide temporary roles/ privileges. For example, this may be used for service user to request certificate during installation time. After installation, the priviege no longer exists



# Auth Service Installaton

There are two modes of installation:

1. Bare Metal
2. Container

## Bare Metal Installation

The daemon will create and use the following files on the OS:

1. /var/log/authservice/authservice.log
2. /var/log/authservice/http.log
3. /var/lib/authservice/* (misc files)
4. /etc//authservice/config.yaml (Configuration)
5. /usr/\*/bin/authservice (executable binary)
6. /etc/authservice/key.pem (TLS key)
7. /etc/authservice/cert.pem (TLS cert)

## Container Installation - Not currently tested/ supported

Since `AAS` is a standalone web service, container deployment is trivial.

All necessary setup options should be readable from environment variables, so the container can be spun up by only passing environment variables

# TLS Configuration -

Currently, there are no requirements for  `AAS` for clients to present certificates. Authentication to clients uses basic authentication.

`AAS` server certificate shall be stored in a the following location `/etc/authservice/cert.pem`. During AAS installation time, the AAS has to request a certificate from the CMS. In order to do this, the installation needs a token that is signed by CMS that has privileges to request an AAS TLS certificate. 

# AAS Features
## Authentication and Authorization

### Authentication Defender

The authenticaiton defender is a designed to thwart disctionary based attacks by locking the account for a specified time. If there are x number of attempts in y time, the account would be locked out for a period of z time. The current default is 5 attempts in 5 minutes and you are locked out for 15 minutes. These may be configured in the config file and is loaded when the daemon restarts.

# Command Line Operations

## Setup

Available setup tasks:
- database
- admin
- server
- tls
- all

### Setup - Database

```bash
> authservice setup database [-force] --db-host=postgres.com --db-port=5432 --db-user=admin --db-pass=password --db-name=aas_db
```
Environment variables `AAS_DB_HOSTNAME`, `AAS_DB_PORT`, `AAS_DB_USERNAME`, `AAS_DB_PASSWORD`, `AAS_DB_NAME` can be used instead of command line flags

##### Database Rotation
Before running this setup, environment variables `AAS_DB_REPORT_MAX_ROWS` and `AAS_DB_REPORT_NUM_ROTATIONS` can be set for configuring database rotation. It will use default values, `AAS_DB_REPORT_MAX_ROWS=100000` and `AAS_DB_REPORT_NUM_ROTATIONS=10` as default value if they are not present while the command is running.

##### SSL/ TLS Connection to database
Communication with database shall by default be over a secure channel even if the database is on the same server as `AAS`. There are several parameters that may be used for this. The following provides an explanation of how this may be used
```bash
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

```bash
> authservice setup server --port=8443
```
Environment variable `AAS_PORT` can be used instead of command line flags

### Setup - TLS

```bash
> authservice setup tls [--force] [--host_names=intel.com,10.1.168.2]
```

Creates a Self Signed TLS Keypair in /etc/authservice/ for quality of life. It is expected that consumers of this product will provide their own key and certificate in /etc/threat-detection before or after running setup, to make `AAS` use those instead.

Environment variable `AAS_TLS_HOST_NAMES` can be used instead of command line flags

`--force` overwrites any existing files, and will always generate a self signed pair.


### Setup - Admin

```bash
> authservice setup admin --user=admin --pass=password
```

Environment variable `AAS_ADMIN_USERNAME` and `AAS_ADMIN_PASSWORD` can be used instead

This task can be used to create multiple admin-users, any duplicated username casus existing user being overwritten with admin privilege.


### Setup - RegHost

```bash
> authservice setup reghost --user=admin --pass=password
```

Environment variable `AAS_REG_HOST_USERNAME` and `AAS_REG_HOST_PASSWORD` can be used instead

This task can be used to create multiple users for host registration, any duplicated username casus existing user being overwritten with host registration privilege.

*Note: whenever this command is called, restarting the service is required to make changes effective*


## Start/Stop

```bash
> authservice start
  Auth Service started
> authservice stop
  Auth Service stopped
```

## Uninstall

```bash
> authservice uninstall [--keep-config]
  Auth Service uninstalled
```
Uninstalls Auth Service, with optional flag to keep configuration

## Help

```bash
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

```bash
> authservice version
    Auth Service v1.0.0 build 9cf83e2
```


# Container Operations

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
