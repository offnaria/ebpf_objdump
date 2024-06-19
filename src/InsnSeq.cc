// SPDX-License-Identifier: MIT

#include <iostream>
#include <iomanip>

#include "InsnSeq.hh"

InsnSeq::InsnSeq(const struct bpf_program *prog) {
    size_t insn_cnt = bpf_program__insn_cnt(prog);
    const struct bpf_insn *prog_insns = bpf_program__insns(prog);
    for (size_t i = 0; i < insn_cnt; ++i) {
        insns.push_back(std::unique_ptr<EbpfInsn>(new EbpfInsn(&prog_insns[i])));
        if (insns.back()->isWide()) {
            ++i;
        }
    }
}

void InsnSeq::printMnemonics() const {
    int i = 0;
    for (const auto &insn : insns) {
        std::cout << std::right << std::setw(8) << i++ << ":\t";
        insn->printMnemonic();
        if (insn->isWide())
            ++i;
    }
}
