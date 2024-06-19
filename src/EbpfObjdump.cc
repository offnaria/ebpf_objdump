// SPDX-License-Identifier: MIT

#include <iostream>

extern "C" {
#include "libbpf.h"
}

#include "EbpfObjdump.hh"

EbpfObjdump::EbpfObjdump(const char *filename) {
    struct bpf_object *obj = bpf_object__open(filename);
    if (libbpf_get_error(obj)) {
        std::cerr << "Failed to open file: " << filename << "\n";
        return;
    }

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (prog == NULL) {
        std::cerr << "No programs found in object file.\n";
        bpf_object__close(obj);
        return;
    }

    struct bpf_program *next_prog = bpf_object__next_program(obj, prog);
    if (next_prog != NULL) {
        std::cerr << "Multiple programs are not supported so far.\n";
        bpf_object__close(obj);
        return;
    }

    insn_seq = std::make_unique<InsnSeq>(prog);

    bpf_object__close(obj);
}

int EbpfObjdump::run() {
    if (insn_seq == nullptr) {
        std::cerr << "Instruction sequence is not initialized.\n";
        return 1;
    }

    // TODO: Implement the run method
    insn_seq->printMnemonics();
    return 0;
}
