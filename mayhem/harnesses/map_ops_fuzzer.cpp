// Upstream's runtime/fuzz/map_ops_fuzzer.cpp, unchanged except for the size of its private
// shared-memory segment. Upstream asks for 64 MiB, which is all of a default container's
// /dev/shm, so the target cannot run next to anything else that uses shared memory (the fuzz
// smoke gate runs targets side by side, and every other bpftime target needs a segment too).
// The harness holds one map at a time, bounded at 64 entries x (64-byte key + 256-byte value),
// times the CPU count for the per-CPU maps (about 20 KiB per CPU). The cap is 4 MiB plus 64 KiB
// per CPU: room for that map with a wide margin, while several live processes of the target fit
// in a 64 MiB /dev/shm.
//
// Upstream names the segment "bpftime_map_ops_fuzz_<pid>" and removes it only from a static
// destructor, which never runs when a process aborts or is killed. A constructor below unlinks
// the segments of such dead processes at start-up, so they cannot accumulate in /dev/shm.
//
// The segment type is swapped by name: every header the upstream file includes is included here
// first (their include guards keep the real type in all bpftime declarations), then
// `managed_shared_memory` is redirected to a subclass that caps the requested size.
#include "bpftime_config.hpp"
#include "bpftime_handler.hpp"
#include "bpftime_shm.hpp"
#include <algorithm>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/bpf.h>
#include <memory>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#include <variant>
#include <vector>

namespace boost::interprocess
{
class mayhem_small_shm : public managed_shared_memory {
    public:
	mayhem_small_shm(create_only_t, const char *name, std::size_t size)
		: managed_shared_memory(create_only, name,
					std::min<std::size_t>(size, cap()))
	{
	}

    private:
	static std::size_t cap()
	{
		long ncpu = sysconf(_SC_NPROCESSORS_CONF);
		if (ncpu < 1)
			ncpu = 1;
		return (std::size_t(4) << 20) + std::size_t(ncpu) * (64u << 10);
	}
};
} // namespace boost::interprocess

namespace
{
__attribute__((constructor)) void mayhem_remove_dead_map_ops_segments()
{
	static const char prefix[] = "bpftime_map_ops_fuzz_";
	DIR *dir = opendir("/dev/shm");
	if (!dir)
		return;
	std::vector<std::string> stale;
	while (struct dirent *e = readdir(dir)) {
		if (strncmp(e->d_name, prefix, sizeof(prefix) - 1) != 0)
			continue;
		char *end = nullptr;
		long pid = strtol(e->d_name + sizeof(prefix) - 1, &end, 10);
		if (pid <= 0 || *end != '\0' || pid == getpid())
			continue;
		if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
			stale.push_back(e->d_name);
	}
	closedir(dir);
	for (const std::string &n : stale)
		shm_unlink(n.c_str());
}
} // namespace

#define managed_shared_memory mayhem_small_shm
#include "../../runtime/fuzz/map_ops_fuzzer.cpp"
#undef managed_shared_memory
