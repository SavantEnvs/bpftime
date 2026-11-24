// Fuzzes bpftime's JSON shared-memory import (bpftimetool import /
// bpftime_import_global_shm_from_json): a JSON dump of prog, map, perf-event
// and link handlers is parsed and each handler is recreated in a shm segment.
// Every input gets a fresh, private segment, so results depend only on it.
#include "bpftime_shm.hpp"
#include "bpftime_shm_internal.hpp"
#include "fuzz_common.hpp"
#include <boost/interprocess/shared_memory_object.hpp>
#include <exception>
#include <unistd.h>

namespace bpftime
{
int bpftime_import_shm_from_json(bpftime_shm &shm, const char *filename);
}

static std::string g_name;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	mayhem_fuzz::init_runtime_env("json");
	g_name = mayhem_fuzz::shm_name("json_private");
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	std::string path = mayhem_fuzz::write_temp(data, size, ".json");
	if (path.empty())
		return 0;
	{
		bpftime::bpftime_shm shm(g_name.c_str(),
					 bpftime::shm_open_type::SHM_REMOVE_AND_CREATE);
		try {
			bpftime::bpftime_import_shm_from_json(shm, path.c_str());
		} catch (const std::exception &) {
			// nlohmann::json reports malformed or mistyped input
			// by throwing (parse_error / type_error /
			// out_of_range); std::stoi does the same for non-numeric
			// keys. That is the importer's documented error path.
		}
	}
	boost::interprocess::shared_memory_object::remove(g_name.c_str());
	unlink(path.c_str());
	return 0;
}
