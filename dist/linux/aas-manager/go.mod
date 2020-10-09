module intel/isecl/tools/populate-users

require (
	github.com/joho/godotenv v1.3.0
	intel/isecl/lib/clients/v3 v3.1.0
	intel/isecl/lib/common/v3 v3.1.0
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.1.0

replace intel/isecl/lib/clients/v3 => github.com/intel-secl/clients/v3 v3.1.0
