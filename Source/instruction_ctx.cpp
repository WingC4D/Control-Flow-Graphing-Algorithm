#include "Context.h"
#include "Lde.h"
using namespace inst;

LdeErrorCodes Context::map(const LPBYTE analysis_address) { using enum Lde::first_byte_traits;
    if (!analysis_address)
        return no_input;

    if (!setLength(getPreDisposition()))
        return instruction_overflow;

    switch (Lde::results[*analysis_address]) {
        case none:
            return *analysis_address == opcodes::RETURN || *analysis_address == 0xC2 ? reached_end_of_function : success;

        case has_mod_rm:
            return analyseModRM(analysis_address);

        case has_mod_rm | prefix:
            return analyseSpecialGroup(analysis_address);

        case has_mod_rm | special:
            return analyseGroup3(analysis_address);

        case has_mod_rm | imm_one_byte:
            if (!incrementLength())
                return instruction_overflow;

            return analyseModRM(analysis_address);

        case has_mod_rm | imm_two_bytes:
            if (!increaseLength(SIZE_OF_WORD))
                return instruction_overflow;

            return analyseModRM(analysis_address);


        case has_mod_rm | imm_four_bytes:
            if (!increaseLength(SIZE_OF_DWORD))
                return instruction_overflow;

            return analyseModRM(analysis_address);


        case has_mod_rm | imm_eight_bytes:
            if (!increaseLength(SIZE_OF_QWORD))
                return instruction_overflow;

            return analyseModRM(analysis_address);

        case has_mod_rm | imm_eight_bytes | imm_four_bytes:
            std::println("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})", reinterpret_cast<void*>(analysis_address));
            return wrong_input;

        case imm_one_byte:
            
            return incrementLength() ? success : instruction_overflow;

        case imm_two_bytes:
            return increaseLength(SIZE_OF_WORD) ? success : instruction_overflow;

        case imm_four_bytes:
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case imm_eight_bytes:
            return increaseLength(SIZE_OF_QWORD) ? success : instruction_overflow;

        case imm_four_bytes | imm_eight_bytes:
            if (*analysis_address == opcodes::CALL || *analysis_address == opcodes::JUMP)
                setRipRelative();

            return increaseLength(isRexW() ? SIZE_OF_QWORD : SIZE_OF_DWORD) ? success :instruction_overflow;

        case prefix:
            if (!incrementPrefixCount()) 
                return prefix_overflow;
            
            if (!incrementLength()) 
                return instruction_overflow;
            
            if ((*analysis_address & 0xF8) == 0x48)
                setRexW();

            else if (!prefix_count && *analysis_address == 0x66)
                shortened = true;

            return map(analysis_address + 1);

        default:
            std::println("[?] WTH Is Going On?");
            return wrong_input;
    }
}

LdeErrorCodes Context::analyseModRM(const LPBYTE preceding_byte_ptr) {
    if (!preceding_byte_ptr) 
        return no_input;

    if (!incrementOpcode())
        return opcode_overflow;

    if (!incrementLength())
        return instruction_overflow;

    BYTE rm_bits = preceding_byte_ptr[1] & RM_MASK;
    switch (preceding_byte_ptr[1] & MOD_MASK) {
    case 0xC0:
        return success;

    case 0x80:
        if (rm_bits == 4) {
            has_SIB = true;
            if (!incrementLength())
                return instruction_overflow;
        }
        return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
        

    case 0x40:
        if (rm_bits == 4) {
            has_SIB = true;
            if (!incrementLength())
                return instruction_overflow;
        }
        return incrementLength() ? success : instruction_overflow;


    default:
        if (rm_bits == 4) {
            has_SIB = true;
            if (!incrementLength())
                return instruction_overflow;

            if (analyseSibBase(preceding_byte_ptr)) {
                if (!increaseLength(SIZE_OF_DWORD))
                    return instruction_overflow;
            }
            return incrementLength() ? success : instruction_overflow;
        }
        if (rm_bits == 5) {
            setRipRelative();
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
        }
        return success;
    }
}

LdeErrorCodes Context::analyseSpecialGroup(LPBYTE preceding_byte_ptr) {
    if (!preceding_byte_ptr) 
        return no_input;

    if (!incrementLength())
        return instruction_overflow;

    if (!incrementOpcode())
        return opcode_overflow;
    
    switch (preceding_byte_ptr[1]) {
        case 0x05:
        case 0x07:
        case 0x34:
        case 0x35:
        case 0x77:
        case 0x31:
        case 0xA2:
        case 0x30:
        case 0x32:
        case 0x06:
        case 0x08:
        case 0x09:
        case 0x0B:
            return success;

        case 0x3A:
        case 0xBA:
            if (!incrementOpcode())
                return opcode_overflow;

            if (!incrementLength())
                return instruction_overflow;

            break;

        case 0x38:
            break;

        default:
            if ((preceding_byte_ptr[1] & 0xF0) == 0x80)
                return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow; 

            break;
    }
    return analyseModRM(1 + preceding_byte_ptr);
}

LdeErrorCodes Context::analyseGroup3(LPBYTE analysis_address) {
    if (!incrementLength())
        return instruction_overflow;
    if (!incrementOpcode())
        return opcode_overflow;

    switch (*analysis_address) {
        case 0xF6:
            return analyseF6(analysis_address);

        case 0xF7:
            return analyseF7(analysis_address);

        default:
            return wrong_input;
    }
}

LdeErrorCodes Context::analyseF6(LPBYTE preceding_byte_ptr) {
    BYTE reg_bits = preceding_byte_ptr[1] & REG_MASK,
         rm_bits  = preceding_byte_ptr[1] & RM_MASK;
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case 0xC0:
            if (reg_bits < 0x10)
                return incrementLength() ? success : instruction_overflow;

            return success;

        case 0x80:
            if (rm_bits == 4) {
                has_SIB = true;
                if (!increaseLength(SIZE_OF_DWORD))
                    return instruction_overflow;
            }
            if (reg_bits < 0x10)
                return increaseLength(SIZE_OF_WORD) ? success : instruction_overflow;

            return incrementLength() ? success : instruction_overflow;

        case 0x40:
            if (rm_bits == 4) {
                has_SIB = true;
                if (!incrementLength())
                    return instruction_overflow;
            }
            if (reg_bits < 0x10)
                return incrementLength() ? success : instruction_overflow;

            return incrementLength() ? success : instruction_overflow;

        default:
            if (rm_bits == 4) {
                has_SIB = true;
                if (analyseSibBase(preceding_byte_ptr + SIZE_OF_WORD))
                    return increaseLength(1 + SIZE_OF_DWORD) ? success : instruction_overflow;

                return incrementLength() ? success : instruction_overflow;
            }
            if (rm_bits == 5) {
                setRipRelative();
                return incrementLength() ? success : instruction_overflow;
            }
            return success;
    }
}

LdeErrorCodes Context::analyseF7(const LPBYTE preceding_byte_ptr) {
    BYTE reg_bits = preceding_byte_ptr[1] & REG_MASK,
         rm_bits  = preceding_byte_ptr[1] & RM_MASK;
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case 0xC0:
            if (reg_bits < 0x10)
                return incrementLength() ? success : instruction_overflow;
            return success;

        case 0x80:
            if (rm_bits == 4) {
                has_SIB = true;
                if (!incrementLength())
                    return instruction_overflow;

                if (analyseSibBase(preceding_byte_ptr))
                    if (!increaseLength(SIZE_OF_DWORD))
                        return instruction_overflow;
            }

            if (reg_bits < 0x10)
                if (!increaseLength(shortened ? SIZE_OF_WORD  : SIZE_OF_DWORD))
                    return instruction_overflow;

            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case 0x40:
            if (rm_bits == 4) {
                has_SIB = true;
                if (!incrementLength())
                    return instruction_overflow;
            }
            if (reg_bits < 0x10)
                return increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD) ? success : instruction_overflow;

            return success;

        default:
            if (reg_bits < 0x10)
                return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

            return success;
    }
}

WORD Context::analyseOpcodeType(_In_ const LPBYTE candidate_addr) { using namespace opcodes;
    switch (*candidate_addr) {
        case 0xC2:
            return ret | _far;

        case RETURN:
            return ret;

        case CALL:
            rip_relative = true;
            return call;

        case JUMP:
            rip_relative = true;
            return jump;

        case 0xEB:
            rip_relative = true;
            return jump | _short;

        case 0x0F:
            switch (candidate_addr[1]) {
                case 0x05:
                    return sys_call;

                case 0x07:
                    return sys_ret;

                case 0x34:
                    return sys_enter;

                case 0x35:
                    return sys_exit;

                default:
                    rip_relative = true;
                    return (candidate_addr[1] & 0xF0) == 0x80 ? conditional | jump : unknown;
            }

        case 0xFF:
            rip_relative = true;
            switch ((candidate_addr[1] & REG_MASK) >> 3) {
                case 0:
                    return indirect_inc;
                case 1:
                    return indirect_dec;
                case 2:
                    return indirect_call;
                case 3:
                    return indirect_far_call;
                case 4:
                    return indirect_jump;
                case 5:
                    return indirect_far_jump;
                case 6:
                    return indirect_push;
                default:
                    rip_relative = false;
                    return unknown;
            }
        default:
            if ((*candidate_addr & 0xF0) == 0x70 || (*candidate_addr & 0xFC) == 0xE0)
                return conditional | jump;
        return unknown;
    }
}

LPBYTE Context::resolveJump(const LPVOID analysis_address) { using namespace opcodes;
    switch (analyseOpcodeType(static_cast<LPBYTE>(analysis_address))) {
        case jump:
        case call:
            return static_cast<LPBYTE>(analysis_address) +
                length +
                *reinterpret_cast<int*>(static_cast<LPBYTE>(analysis_address) + getPreDisposition());

        case jump | _short:
        case jump | conditional:
            return static_cast<LPBYTE>(analysis_address) +
                length + 
                *(static_cast<signed char*>(analysis_address) + 1);

        case indirect_call:
        case indirect_jump:
            return *reinterpret_cast<LPBYTE*>(static_cast<LPBYTE>(analysis_address) +
                length + 
                *reinterpret_cast<int *>(
                    static_cast<LPBYTE>(analysis_address) + getPreDisposition()
                )
            );

        default:
            return nullptr;
    }
}
