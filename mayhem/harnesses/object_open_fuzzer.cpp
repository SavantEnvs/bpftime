// Fuzzes eBPF ELF object loading (bpftime_object_open, the path behind
// `bpftime-aot build` and the object-file tools): libbpf parses the ELF, BTF
// and relocations, and bpftime extracts each program's instructions.
#include "bpftime_object.hpp"
#include "bpftime_prog.hpp"
#include "fuzz_common.hpp"
#include <exception>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	mayhem_fuzz::init_runtime_env("obj");
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	std::string path = mayhem_fuzz::write_temp(data, size, ".o");
	if (path.empty())
		return 0;
	try {
		bpftime::bpftime_object *obj =
			bpftime::bpftime_object_open(path.c_str());
		if (obj) {
			int count = 0;
			for (bpftime::bpftime_prog *p =
				     bpftime::bpftime_object__next_program(
					     obj, nullptr);
			     p && count < 64;
			     p = bpftime::bpftime_object__next_program(obj, p))
				count++;
			bpftime::bpftime_object_close(obj);
		}
	} catch (const std::exception &) {
	}
	unlink(path.c_str());
	return 0;
}
