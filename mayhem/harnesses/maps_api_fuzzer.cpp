// Fuzzes the fd-based map API of bpftime_shm (what the emulated bpf()
// syscall and the map helpers call): map creation for every userspace map
// type, including map-in-map with an inner map, then a sequence of
// lookup/update/delete/next-key/push/pop/peek operations on fuzzed fds
// (valid, unallocated, negative and out of range). Each input gets a fresh
// private segment.
#include "bpftime_shm.hpp"
#include "bpftime_shm_internal.hpp"
#include "fuzz_common.hpp"
#include <boost/interprocess/shared_memory_object.hpp>
#include <exception>
#include <vector>

using bpftime::bpf_map_type;

static std::string g_name;

static const bpf_map_type kTypes[] = {
	bpf_map_type::BPF_MAP_TYPE_HASH,
	bpf_map_type::BPF_MAP_TYPE_ARRAY,
	bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY,
	bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH,
	bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY,
	bpf_map_type::BPF_MAP_TYPE_STACK_TRACE,
	bpf_map_type::BPF_MAP_TYPE_LRU_HASH,
	bpf_map_type::BPF_MAP_TYPE_LPM_TRIE,
	bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS,
	bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS,
	bpf_map_type::BPF_MAP_TYPE_QUEUE,
	bpf_map_type::BPF_MAP_TYPE_STACK,
	bpf_map_type::BPF_MAP_TYPE_RINGBUF,
	bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER,
};

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	mayhem_fuzz::init_runtime_env("maps");
	g_name = mayhem_fuzz::shm_name("maps_private");
	return 0;
}

static constexpr int kMaxFd = 8;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	mayhem_fuzz::reader in(data, size);
	{
		bpftime::bpftime_shm shm(g_name.c_str(),
					 bpftime::shm_open_type::SHM_REMOVE_AND_CREATE);
		try {
			// Up to 3 maps at fds 1..3; map-in-map values are fds
			// of the maps created before them.
			int nmaps = 1 + in.byte() % 3;
			uint32_t max_key = 1, max_val = 1;
			for (int i = 0; i < nmaps; i++) {
				bpftime::bpf_map_attr attr;
				attr.type = (int)kTypes[in.byte() %
							(sizeof(kTypes) /
							 sizeof(kTypes[0]))];
				attr.key_size = in.byte() % 65;
				attr.value_size = in.byte() % 257;
				attr.max_ents = in.byte() % 65;
				attr.flags = in.byte();
				attr.map_extra = in.byte() % 16;
				if (attr.type ==
				    (int)bpf_map_type::BPF_MAP_TYPE_RINGBUF)
					attr.max_ents = 4096u << (in.byte() % 3);
				shm.add_bpf_map(1 + i, "fuzz_map", attr);
				max_key = std::max(max_key, attr.key_size);
				max_val = std::max(max_val, attr.value_size);
			}
			// Value buffers are sized for the largest per-CPU
			// layout a map here can use from the syscall path.
			size_t vbuf = (size_t)max_val * 256 + 64;
			std::vector<uint8_t> key(max_key + 64), next(max_key + 64),
				value(vbuf);
			for (int op_i = 0; op_i < 128 && !in.empty(); op_i++) {
				uint8_t op = in.byte();
				uint8_t fdsel = in.byte();
				int fd;
				if (fdsel < 0xf0)
					fd = fdsel % kMaxFd;
				else
					fd = (int)in.u32();
				bool sys = op & 0x80;
				uint64_t flags = (op >> 4) & 0x7;
				in.fill(key.data(), max_key);
				switch (op & 0xf) {
				case 0:
					in.fill(value.data(), max_val);
					shm.bpf_map_update_elem(fd, key.data(),
								value.data(),
								flags, sys);
					break;
				case 1: {
					const void *p = shm.bpf_map_lookup_elem(
						fd, key.data(), sys);
					if (p && fd >= 0 && fd < kMaxFd) {
						uint32_t vs =
							shm.bpf_map_value_size(fd);
						if (vs <= value.size())
							memcpy(value.data(), p,
							       vs);
					}
					break;
				}
				case 2:
					shm.bpf_delete_elem(fd, key.data(), sys);
					break;
				case 3:
					shm.bpf_map_get_next_key(fd, key.data(),
								 next.data(),
								 sys);
					break;
				case 4:
					shm.bpf_map_get_next_key(fd, nullptr,
								 next.data(),
								 sys);
					break;
				case 5:
					in.fill(value.data(), max_val);
					shm.bpf_map_push_elem(fd, value.data(),
							      flags, sys);
					break;
				case 6:
					shm.bpf_map_pop_elem(fd, value.data(),
							     sys);
					break;
				case 7:
					shm.bpf_map_peek_elem(fd, value.data(),
							      sys);
					break;
				case 8:
					shm.bpf_map_lookup_and_delete_elem(
						fd, key.data(), value.data(),
						sys);
					break;
				case 9:
					shm.bpf_map_value_size(fd);
					break;
				case 10:
					if (fd >= 0 && fd < kMaxFd)
						shm.dup_bpf_map(fd, 1 + (op >> 4) % kMaxFd);
					break;
				case 11:
					if (fd >= 0 && fd < kMaxFd)
						shm.close_fd(fd);
					break;
				default:
					break;
				}
			}
		} catch (const std::exception &) {
			// Map constructors reject invalid attributes by
			// throwing (e.g. std::invalid_argument, bad_alloc of a
			// boost segment); that is their documented error path.
		}
	}
	boost::interprocess::shared_memory_object::remove(g_name.c_str());
	return 0;
}
