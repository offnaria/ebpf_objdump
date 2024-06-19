// SPDX-License-Identifier: MIT

#if !defined(INSTSEQ_HH)
#define INSTSEQ_HH

#include <list>
#include <memory>

extern "C" {
#include "libbpf.h"
}

#include "EbpfInsn.hh"

class InsnSeq {
    std::list<std::unique_ptr<EbpfInsn>> insns;
public:
    InsnSeq(const struct bpf_program *prog);
    void printMnemonics() const;
};

#endif // INSTSEQ_HH
