// SPDX-License-Identifier: MIT

#include <format>
#include <print>
#include <cstdint>

#include "EbpfInsn.hh"

enum class EbpfInsnCls {LD, LDX, ST, STX, ALU, JMP, JMP32, ALU64};

enum class EbpfInsnRegs {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10};
struct regs {
    enum EbpfInsnRegs dst;
    enum EbpfInsnRegs src;
};

// ALU, JMP
enum class EbpfInsnCodeALU {ADD, SUB, MUL, DIV_SDIV, OR, AND, LSH, RSH, NEG, MOD_SMOD, XOR, MOV_MOVSX, ARSH, END};
enum class EbpfInsnCodeJMP {JA, JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, CALL, EXIT, JLT, JLE, JSLT, JSLE};
enum class EbpfInsnSource {K, X};

class EbpfInsnALUJMP : public EbpfInsnSpecific {
    struct opcode {
        union {
            enum EbpfInsnCodeALU alu;
            enum EbpfInsnCodeJMP jmp;
        } code;
        enum EbpfInsnSource s;
        enum EbpfInsnCls cls;
    } opcode;
    struct regs regs;
    int16_t offset;
    int32_t imm;
public:
    EbpfInsnALUJMP(const struct bpf_insn *insn) {
        const int code = insn->code >> 4;
        const int s = (insn->code >> 3) & 0x1;
        const auto cls = static_cast<enum EbpfInsnCls>(insn->code & 0x7);
        const int dst = insn->dst_reg;
        const int src = insn->src_reg;
        const int off = insn->off;
        const int imm_local = insn->imm;
        std::string mnemonic;
        // TODO: Correct the mnemonic strings.
        if ((cls == EbpfInsnCls::ALU) || (cls == EbpfInsnCls::ALU64)) {
            switch (static_cast<enum EbpfInsnCodeALU>(code)) {
                case EbpfInsnCodeALU::ADD: mnemonic = std::format("r{} += {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::SUB: mnemonic = std::format("r{} -= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::MUL: mnemonic = std::format("r{} *= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::DIV_SDIV: mnemonic = std::format("r{} /= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::OR: mnemonic = std::format("r{} |= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::AND: mnemonic = std::format("r{} &= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::LSH: mnemonic = std::format("r{} <<= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::RSH: mnemonic = std::format("r{} >>= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::NEG: mnemonic = std::format("r{} = -r{}", dst, src); break;
                case EbpfInsnCodeALU::MOD_SMOD: mnemonic = std::format("r{} %= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::XOR: mnemonic = std::format("r{} ^= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::MOV_MOVSX: mnemonic = std::format("r{} = {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::ARSH: mnemonic = std::format("r{} >>= {}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local)); break;
                case EbpfInsnCodeALU::END: mnemonic = std::format("r{} = {}{}(r{})", dst, (cls == EbpfInsnCls::ALU) ? (s ? "htobe" : "htole") : "bswap", imm, dst); break;
                default: mnemonic = "unknown";
            }
            opcode.code.alu = static_cast<enum EbpfInsnCodeALU>(code);
        } else {
            switch (static_cast<enum EbpfInsnCodeJMP>(code)) {
                case EbpfInsnCodeJMP::JA: mnemonic = std::format("goto {:+#x}", (cls == EbpfInsnCls::JMP) ? off : imm_local); break;
                case EbpfInsnCodeJMP::JEQ: mnemonic = std::format("if r{} == {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JGT: mnemonic = std::format("if r{} > {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JGE: mnemonic = std::format("if r{} >= {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JSET: mnemonic = std::format("if r{} & {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JNE: mnemonic = std::format("if r{} != {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JSGT: mnemonic = std::format("if r{} > {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JSGE: mnemonic = std::format("if r{} >= {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::CALL: mnemonic = std::format("call {:#x}", imm_local); break;
                case EbpfInsnCodeJMP::EXIT: mnemonic = "exit"; break;
                case EbpfInsnCodeJMP::JLT: mnemonic = std::format("if r{} < {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JLE: mnemonic = std::format("if r{} <= {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JSLT: mnemonic = std::format("if r{} < {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                case EbpfInsnCodeJMP::JSLE: mnemonic = std::format("if r{} <= {} goto {:+#x}", dst, s ? std::format("r{}", src) : std::format("{:#x}", imm_local), off); break;
                default: mnemonic = "unknown";
            }
            opcode.code.jmp = static_cast<enum EbpfInsnCodeJMP>(code);
        }
        setMnemonic(mnemonic);
        opcode.s = static_cast<enum EbpfInsnSource>(s);
        opcode.cls = cls;
        regs.dst = static_cast<enum EbpfInsnRegs>(dst);
        regs.src = static_cast<enum EbpfInsnRegs>(src);
        offset = static_cast<int16_t>(off);
        imm = static_cast<int32_t>(imm_local);
    };
    // struct opcode getOpcode() const {
    //     return opcode;
    // };
};

// LD, LDX, ST, STX
enum class EbpfInsnMode {IMM, ABS, IND, MEM, MEMSX, ATOMIC = 6};
enum class EbpfInsnSize {W, H, B, DW};

class EbpfInsnLDST : public EbpfInsnSpecific {
    struct opcode {
        enum EbpfInsnMode mode;
        enum EbpfInsnSize sz;
        enum EbpfInsnCls cls;
    } opcode;
    struct regs regs;
    int16_t offset;
    int32_t imm;
    int getSize(EbpfInsnSize sz) {
        switch (sz) {
            case EbpfInsnSize::W: return 32;
            case EbpfInsnSize::H: return 16;
            case EbpfInsnSize::B: return 8;
            case EbpfInsnSize::DW: return 64;
            default: return 0;
        }
    }
public:
    EbpfInsnLDST(const struct bpf_insn *insn) {
        const int mode = insn->code >> 5;
        const auto sz = static_cast<enum EbpfInsnSize>((insn->code >> 3) & 0x3);
        const auto cls = static_cast<enum EbpfInsnCls>(insn->code & 0x7);
        const int dst = insn->dst_reg;
        const int src = insn->src_reg;
        const int off = insn->off;
        const int imm_local = insn->imm;
        const int64_t next_imm = (insn + 1)->imm;
        std::string mnemonic;
        // TODO: Correct the mnemonic strings.
        switch (static_cast<enum EbpfInsnMode>(mode)) {
            case EbpfInsnMode::IMM:
                switch (static_cast<enum EbpfInsnRegs>(src)) {
                    case EbpfInsnRegs::r0: mnemonic = std::format("r{} = {:#x} ll", dst, (next_imm << 32) | imm_local); is_wide = 1; break;
                    case EbpfInsnRegs::r1: mnemonic = std::format("r{} = map_by_fd({:#x})", dst, imm_local); break;
                    case EbpfInsnRegs::r2: mnemonic = std::format("r{} = map_val(map_by_fd({:#x}) + {:#x})", dst, imm_local, next_imm); is_wide = 1; break;
                    case EbpfInsnRegs::r3: mnemonic = std::format("r{} = var_addr({:#x})", dst, imm_local); break;
                    case EbpfInsnRegs::r4: mnemonic = std::format("r{} = code_addr({:#x})", dst, imm_local); break;
                    case EbpfInsnRegs::r5: mnemonic = std::format("r{} = map_by_idx({:#x})", dst, imm_local); break;
                    case EbpfInsnRegs::r6: mnemonic = std::format("r{} = map_val(map_by_idx({:#x}) + {:#x})", dst, imm_local, next_imm); is_wide = 1; break;
                    default: mnemonic = std::format("unknown");
                }
            break;
            // case EbpfInsnMode::ABS: mnemonic = std::format("r{} = *(u{} *){}", dst, (sz == 0) ? 32 : 64, imm_local); break;
            // case EbpfInsnMode::IND: mnemonic = std::format("r{} = *(u{} *)r{}", dst, (sz == 0) ? 32 : 64, src); break;
            case EbpfInsnMode::MEM:
                switch (cls) {
                    case EbpfInsnCls::LD: mnemonic = "unknown"; break;
                    case EbpfInsnCls::LDX: mnemonic = std::format("r{} = *(u{} *) (r{} + {:#x})", dst, getSize(sz), src, off); break;
                    default: mnemonic = std::format("*(u{} *) (r{} + {:+#x}) = {}", getSize(sz), dst, off, (cls == EbpfInsnCls::ST) ? std::format("{:#x}", imm_local) : std::format("r{}", src));
                }
            break;
            case EbpfInsnMode::MEMSX: mnemonic = std::format("r{} = *(s{} *) (r{} + {:#x})", dst, getSize(sz), src, off); break;
            // case EbpfInsnMode::ATOMIC: mnemonic = std::format("r{} = atomic_{}{}", dst, (sz == 0) ? "add" : "xchg", (sz == 0) ? "l" : "q"); break;
            default: mnemonic = "unknown";
        }
        setMnemonic(mnemonic);
        opcode.mode = static_cast<enum EbpfInsnMode>(mode);
        opcode.sz = sz;
        opcode.cls = cls;
        regs.dst = static_cast<enum EbpfInsnRegs>(dst);
        regs.src = static_cast<enum EbpfInsnRegs>(src);
        offset = static_cast<int16_t>(off);
        imm = static_cast<int32_t>(imm_local);
    };
    // struct opcode getOpcode() const {
    //     return opcode;
    // };
};

EbpfInsnSpecific::EbpfInsnSpecific(const struct bpf_insn *insn) {
    setMnemonic("unknown");
}

void EbpfInsnSpecific::setMnemonic(const std::string mnemonic) {
    this->mnemonic = mnemonic;
}

std::string EbpfInsnSpecific::getMnemonic() const {
    return mnemonic;
}

bool EbpfInsnSpecific::isWide() const {
    return is_wide;
}

EbpfInsn::EbpfInsn(const struct bpf_insn *insn) {
    const auto cls = static_cast<enum EbpfInsnCls>(insn->code & 0x07);
    if (cls >= EbpfInsnCls::ALU) {
        insn_specific = std::unique_ptr<EbpfInsnSpecific>(new EbpfInsnALUJMP(insn));
        return;
    }
    insn_specific = std::unique_ptr<EbpfInsnSpecific>(new EbpfInsnLDST(insn));
}

void EbpfInsn::printMnemonic() const {
    std::print("{}\n", insn_specific->getMnemonic());
}

bool EbpfInsn::isWide() const {
    return insn_specific->isWide();
}
