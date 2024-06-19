// SPDX-License-Identifier: MIT

#if !defined(EBPFINSN_HH)
#define EBPFINSN_HH

#include <string>
#include <memory>

extern "C" {
#include "libbpf.h"
}

class EbpfInsnSpecific {
    std::string mnemonic;
public:
    bool is_wide = 0;
    EbpfInsnSpecific() {};
    EbpfInsnSpecific(const struct bpf_insn *insn);
    void setMnemonic(const std::string mnemonic);
    std::string getMnemonic() const;
    bool isWide() const;
};

class EbpfInsn {
    std::unique_ptr<EbpfInsnSpecific> insn_specific;
public:
    EbpfInsn();
    EbpfInsn(const struct bpf_insn *insn);
    void printMnemonic() const;
    bool isWide() const;
};

#endif // EBPFINSN_HH
