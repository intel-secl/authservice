# Auth Service Low Level Documentation

## Acronyms

|     | Description                 |
|-----|-----------------------------|
| AAS | Authentication & Authorization Service    |



# Overview

The `Auth Service` is a web service whose purpose is to authenticate a user and return has the mapping or users to roles

The `Auth Service` has following core functionalities:

## User Stories
### Create, Read, Update, Delete Roles
Based on the privileges of the user, a user(typically an admin) need the ability to create, read, update and delete roles. The roles may have `service` attribute which indicates what microservice the role belongs to. For instance, you can have a `WLS Reporter` role as well as a `HVS Reporter` role. In this case, role comprises of two parts - `service` (WLS vs HVS) and the `role name` - `Reporter`

*Update will not be part of Phase 1*

### Create, Read, Update, Delete Users
Based on the privileges of the user, a user(typically an admin) need the ability to create, read, update and delete roles.

*Update will not be part of Phase 1*

### Assign, Read, Update and Remove user roles
A user can be assigned one or more roles. When the user no longer needs the role, these role associations may be deleted. This task is performed by someone with the appropriate privileges (typically an admin)

*Update will not be part of Phase 1*

### Associate a `scope` when assigning a role permission
When a role is associated with a user, a `scope` may be associated with that user-role mapping. This is to provide relevant context to the application that needs extra infromation in addition to the user role association. An example of this when a certificte request is made to CMS with a CSR, in addition to having the `CMS:CertRequestor` role, there should be some contextual information that indicates which certificates the user may obtain.

### Obtain a token
A user can obtain a token with credentials (user name as password). The returned token will contain roles and scope. Beofre the token is provided to the user, the following must be completed
1. The user name and password shall be verified
2. Obtain list of roles and scope that is associated with the user.

The user can choose to restrict the token by the following attributes - not in scope for Phase 1
    1. service
    2. Role
    3. time (so instance, I only want a token that is valid for 5 mins to carry out a specific task )


### Install AAS
A user should be able to install the AAS service. As part of the installation process, the following items should be accomplished
  1. Set up a database
  2. Install root certificate of CMS
  3. Request TLS Certificate from CMS, store it and configure https with TLS certificate a
  4. Request JWT signing certificate from CMS, store it - to be used for token signing
  5. Create an admin user.
  6. Preload roles in AAS
  7. Preload users in AAS
  8. Preload user-roles in AAS
  9. A daemon is configured to run the AAS service and started

## API Endpoints

## Token related

### POST `/aas/token`
Retrieve a token with supplied user credentials. Return a map of roles assiociated with the user as well optional scope that contains contextual information pertaining to the user-role mapping.

- Authorization: `HTTP Basic Authentication`
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

### GET `/aas/users/{id-uuidv4}`

Get a single user by ID

- Authorization: `Bearer Token`

Retrieve information regarding a specific user
- `GET /aas/users/123e4567-e89b-12d3-a456-426655440000`

Example Response:

```json
{
    "user_id": "223e4567-e89b-12d3-a456-426655440000",
    "username": "admin",
},
```



### DELETE `/aas/users/{user_id}`

- Authorization: `Bearer Token`

Response: success/failure

deletes user from database with specific user id. Deleting a record using this method is a 2-step process as we need to first obtain the user uuid using the `GET` method.


### DELETE `/aas/users?username=myname@intel.com` - Not implemented

- Authorization: `Bearer Token`

Response: success/failure

Not sure if we should have this interface ??
*Will not be part of Phase 1*
### POST `/aas/users/{userid}/change_password` - Not implemented
(not available in intial version)

used to change password for the user if they know the existing password.
Can this be used for an admin to change password for someone else?
Here the authorization should probably be basic authentication. We should not be using a
token to change the password since some service that has obtained the token should not
be able to change the password

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

Create a role in AAS. In the below, the context is optional. Usage of context depends on the microservice.

- Authorization: `Bearer Token`
- Content-Type: `application/json`

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

### GET `/aas/roles/{id-uuidv4}`

Get a single role by ID

- Authorization: `Bearer Token`

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

## User Role Management
### POST /api/users/{userid}/roles

Assign a role to the user. User roles association is only allowed using ids. You have to call `GET /aas/roles` to determine th ids

- Authorization: `Bearer Token`
- Content-Type: `application/json`

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

### DELETE /api/users/{userid}/roles/{role_id}

Delete a role association with the user. Right now, there are no bulk operation to delete multiple role associations

- Authorization: `Bearer Token`
- Content-Type: `application/json`


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
- jwt
- cms
- tls
- all

### Setup - Database

```bash
> authservice setup database [-force] --db-host=postgres.com --db-port=5432 --db-user=admin --db-pass=password --db-name=aas_db
```
Environment variables `AAS_DB_HOSTNAME`, `AAS_DB_PORT`, `AAS_DB_USERNAME`, `AAS_DB_PASSWORD`, `AAS_DB_NAME` can be used instead of command line flags


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
