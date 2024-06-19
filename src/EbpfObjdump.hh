// SPDX-License-Identifier: MIT

#if !defined(EBPFOBJDUMP_HH)
#define EBPFOBJDUMP_HH

#include <memory>

#include "InsnSeq.hh"

class EbpfObjdump {
    std::unique_ptr<InsnSeq> insn_seq;
public:
    EbpfObjdump(const char *filename);
    int run();
};

#endif // EBPFOBJDUMP_HH
