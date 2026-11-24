// Shared helpers for the mayhem/ bpftime harnesses.
#pragma once
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <dirent.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace mayhem_fuzz
{
// Reads the input front to back; bytes past the end read as zero.
class reader {
    public:
	reader(const uint8_t *d, size_t n) : data(d), size(n)
	{
	}
	bool empty() const
	{
		return pos >= size;
	}
	uint8_t byte()
	{
		return pos < size ? data[pos++] : 0;
	}
	uint32_t u32()
	{
		uint32_t v = 0;
		fill(&v, sizeof(v));
		return v;
	}
	void fill(void *dst, size_t len)
	{
		size_t avail = pos < size ? std::min(len, size - pos) : 0;
		if (avail)
			memcpy(dst, data + pos, avail);
		memset((uint8_t *)dst + avail, 0, len - avail);
		pos += avail;
	}
	const uint8_t *rest(size_t *len) const
	{
		*len = pos < size ? size - pos : 0;
		return data + (pos < size ? pos : size);
	}

    private:
	const uint8_t *data;
	size_t size;
	size_t pos = 0;
};

// One shared-memory name per target, role and process. Mayhem runs several
// fuzzer and triage processes of a target at once on one /dev/shm, so a name
// shared by them would let one process's SHM_REMOVE_AND_CREATE unlink and
// race another's segment. With the pid in the name every live process owns
// its segment alone.
inline std::string shm_name(const char *tag)
{
	return std::string("mayhem_bpftime_") + tag + "_" +
	       std::to_string((long)getpid());
}

// A process that aborts or times out never removes its own segment, so at
// start-up unlink every "mayhem_bpftime_*_<pid>" segment whose pid no longer
// exists. Segments of live processes (kill() succeeds or fails with EPERM)
// are never touched.
inline void remove_stale_shm()
{
	static const char prefix[] = "mayhem_bpftime_";
	DIR *dir = opendir("/dev/shm");
	if (!dir)
		return;
	std::vector<std::string> stale;
	while (struct dirent *e = readdir(dir)) {
		std::string n = e->d_name;
		if (n.rfind(prefix, 0) != 0)
			continue;
		size_t us = n.rfind('_');
		if (us == std::string::npos || us + 1 >= n.size())
			continue;
		char *end = nullptr;
		long pid = strtol(n.c_str() + us + 1, &end, 10);
		if (pid <= 0 || *end != '\0' || pid == (long)getpid())
			continue;
		if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
			stale.push_back(n);
	}
	closedir(dir);
	for (const std::string &n : stale)
		shm_unlink(n.c_str());
}

// Configure the runtime once, before any shm is created: a small segment and
// quiet logging. Both are process-wide and never changed afterwards.
inline void init_runtime_env(const char *tag)
{
	remove_stale_shm();
	setenv("BPFTIME_SHM_MEMORY_MB", "2", 1);
	setenv("BPFTIME_GLOBAL_SHM_NAME", shm_name(tag).c_str(), 1);
	setenv("SPDLOG_LEVEL", "off", 1);
	setenv("BPFTIME_LOG_OUTPUT", "/dev/null", 1);
	setenv("BPFTIME_VM_NAME", "ubpf", 1);
}

// Write the input to a fresh file under $TMPDIR; returns "" on failure.
inline std::string write_temp(const uint8_t *data, size_t size,
			      const char *suffix)
{
	const char *tmp = getenv("TMPDIR");
	std::string path = std::string(tmp && *tmp ? tmp : "/tmp") +
			   "/bpftime_fuzz_XXXXXX" + suffix;
	int fd = mkstemps(path.data(), (int)strlen(suffix));
	if (fd < 0)
		return "";
	size_t off = 0;
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) {
			close(fd);
			unlink(path.c_str());
			return "";
		}
		off += (size_t)w;
	}
	close(fd);
	return path;
}
} // namespace mayhem_fuzz
