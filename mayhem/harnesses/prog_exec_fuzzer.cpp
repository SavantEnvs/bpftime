// Fuzzes eBPF bytecode loading and execution in bpftime's userspace VM
// (bpftime_prog -> compat ubpf). Input: one byte of context length, the
// context memory, then the instruction stream. uBPF runs with its runtime
// bounds checking on (the default bpftime configures), so a program's
// out-of-range load/store is rejected by the VM, not executed.
#include "bpftime_prog.hpp"
#include "bpftime_shm.hpp"
#include "fuzz_common.hpp"
#include <boost/interprocess/shared_memory_object.hpp>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	mayhem_fuzz::init_runtime_env("prog");
	// The VM's bounds predicate and lddw map relocation consult the
	// global segment; it holds no maps and no input ever adds one.
	bpftime_initialize_global_shm(
		bpftime::shm_open_type::SHM_REMOVE_AND_CREATE);
	atexit(bpftime_remove_global_shm);
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	mayhem_fuzz::reader in(data, size);
	uint8_t ctx_len = in.byte();
	std::vector<uint8_t> ctx(ctx_len ? ctx_len : 1);
	in.fill(ctx.data(), ctx_len);
	size_t rest = 0;
	const uint8_t *code = in.rest(&rest);
	size_t n = rest / sizeof(ebpf_inst);
	if (n == 0)
		return -1;
	std::vector<ebpf_inst> insns(n);
	memcpy(insns.data(), code, n * sizeof(ebpf_inst));
	try {
		bpftime::bpftime_prog prog(insns.data(), n, "fuzz_prog");
		if (prog.bpftime_prog_load(false) < 0)
			return 0;
		uint64_t ret = 0;
		prog.bpftime_prog_exec(ctx.data(), ctx_len, &ret);
	} catch (const std::exception &) {
	}
	return 0;
}
