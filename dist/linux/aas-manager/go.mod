module intel/isecl/tools/populate-users

go 1.12

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients v0.0.0
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v2.0/develop

replace intel/isecl/lib/clients => gitlab.devtools.intel.com/sst/isecl/lib/clients.git v2.0/develop
