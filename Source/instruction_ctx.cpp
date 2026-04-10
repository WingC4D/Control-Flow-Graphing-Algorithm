#include "Context.h"
#include "Lde.h"
using namespace inst;

//Main instruction decoding dispatcher.
Context::Status Context::map(const BYTE * const analysis_address) { using enum Lde::first_byte_traits; using enum Status;
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
            std::println("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})", reinterpret_cast<const void*>(analysis_address));
            return wrong_input;

        case imm_one_byte:
            return incrementLength() ? success : instruction_overflow;

        case imm_two_bytes:
            return increaseLength(SIZE_OF_WORD) ? success  : instruction_overflow;

        case imm_four_bytes:
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case imm_eight_bytes:
            return increaseLength(SIZE_OF_QWORD) ? success : instruction_overflow;

        case imm_four_bytes | imm_eight_bytes:
            if (*analysis_address == opcodes::CALL || *analysis_address == opcodes::JUMP)
                setRipRelative();

            return increaseLength(rex_w ? SIZE_OF_QWORD : SIZE_OF_DWORD) ? success :instruction_overflow;

        case prefix:
            if (!incrementPrefixCount()) 
                return prefix_overflow;
            
            if (!incrementLength()) 
                return instruction_overflow;
            
            if ((*analysis_address & 0xF8) == 0x48)
                rex_w = true;

            else if (!prefix_count && *analysis_address == 0x66)
                shortened = true;

            return map(analysis_address + 1);
        
        default:
            std::println("[?] WTH Is Going On?");
            return wrong_input;
    }
}

Context::Status Context::analyseModRM(const BYTE* const preceding_byte_ptr) {
    if (!preceding_byte_ptr) 
        return no_input;

    if (!incrementOpcode())  
        return opcode_overflow;
                             
    if (!incrementLength())  
        return instruction_overflow;

    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case 0xC0:
            return success;

        case 0x80:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case 0x40:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            return incrementLength() ? success : instruction_overflow;

        default:
            if ((preceding_byte_ptr[1] & mod_rm::RM_MASK) == 4) {
                has_SIB = true;
                return increaseLength(analyseSibBase(preceding_byte_ptr) ? SIZE_OF_BYTE + SIZE_OF_DWORD : SIZE_OF_BYTE) ? success : instruction_overflow;
            }
            if ((preceding_byte_ptr[1] & RM_MASK) != 5) 
                return success;

            rip_relative = true;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
    }
}

Context::Status Context::analyseSpecialGroup(const BYTE* const preceding_byte_ptr) {
    if (!preceding_byte_ptr) 
        return no_input;

    if (!incrementLength())
        return instruction_overflow;

    if (!incrementOpcode())
        return opcode_overflow;

    switch (preceding_byte_ptr[1]) {
        case 0x05:
        case 0x06:
        case 0x07:
        case 0x08:
        case 0x09:
        case 0x30:
        case 0x31:
        case 0x32:
        case 0x34:
        case 0x35:
        case 0x77:
        case 0xA2:
        case 0x0B:
            return success;

        case 0x38:
            break;

        case 0x3A:
        case 0xBA:
            if (!incrementOpcode())
                return opcode_overflow;

            if (!incrementLength())
                return instruction_overflow;

            break;

        default:
            if ((preceding_byte_ptr[1] & 0xF0) != 0x80)
                break;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
    }
    return analyseModRM(1 + preceding_byte_ptr);
}

Context::Status Context::analyseGroup3(const BYTE* const analysis_address) {
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

Context::Status Context::analyseF6(const BYTE* const preceding_byte_ptr) {
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case 0xC0:
            return analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE);

        case 0x80:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_DWORD))
                return instruction_overflow;

            if (success != analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            return incrementLength() ? success : instruction_overflow;

        case 0x40:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            if (success != analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            return incrementLength() ? success : instruction_overflow;

        default:
            if (success != analyseRM4nSIB(preceding_byte_ptr, SIZE_OF_BYTE, SIZE_OF_DWORD))
                return instruction_overflow;

            if ((preceding_byte_ptr[1] & RM_MASK) != 5) 
                return success;

            setRipRelative();
            return incrementLength() ? success : instruction_overflow;
    }
}

Context::Status Context::analyseF7(const BYTE* const preceding_byte_ptr) {
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case 0xC0:
            return analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE);

        case 0x80:
            if (!increaseLength(SIZE_OF_DWORD))
                return instruction_overflow;

            if (success != analyseRM4nSIB(preceding_byte_ptr, SIZE_OF_BYTE, SIZE_OF_DWORD))
                return instruction_overflow;
            
            if ((preceding_byte_ptr[1] & REG_MASK) < 0x10)
                return increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD) ? success : instruction_overflow;

            return  success ;

        case 0x40:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;

            if ((preceding_byte_ptr[1] & REG_MASK) > 0x10)
                return success;

            return increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD) ? success : instruction_overflow;

        default:
            return analyseRegBits(preceding_byte_ptr, SIZE_OF_DWORD);
    }
}

WORD Context::analyseOpcodeType(_In_ const BYTE * const candidate_addr) { using namespace opcodes;
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

const BYTE * Context::resolveJump(const BYTE* const analysis_address) { using enum opcodes::types;
    switch (analyseOpcodeType(analysis_address)) {
        case jump:
        case call:
            return analysis_address + length + *reinterpret_cast<const int* const>(analysis_address + getPreDisposition());

        case jump | _short:
        case jump | conditional:
            return analysis_address + length + *reinterpret_cast<const signed char* const>(analysis_address + getPreDisposition());

        case indirect_call:
        case indirect_jump:
            return *reinterpret_cast<const BYTE * const *>(analysis_address + length + *reinterpret_cast<const int * const>(analysis_address + getPreDisposition()));

        default:
            return nullptr;
    }
    
}