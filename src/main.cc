// SPDX-License-Identifier: MIT

#include <iostream>

#include "EbpfObjdump.hh"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <eBPF object file>\n";
        return 1;
    }

    EbpfObjdump ebpf_objdump(argv[1]);
    return ebpf_objdump.run();
}
