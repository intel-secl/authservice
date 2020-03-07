module intel/isecl/tools/populate-users

go 1.12

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients v0.0.0
	intel/isecl/lib/common v0.0.0
)

replace intel/isecl/lib/common => github.com/intel-secl/common v2.0

replace intel/isecl/lib/clients => github.com/intel-secl/clients v2.0
