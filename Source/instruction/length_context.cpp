#include "length_disassembly_engine/instruction/length_context.h"
using namespace inst;

//Main instruction decoding dispatcher.
Context::Status Context::map(const BYTE * const analysis_address) { using enum FirstByteTraits; using enum Status;
    if (!analysis_address)
        return no_input;
    if (!setLength(getPreDisposition()))
        return instruction_overflow;
/*   
    if (analysis_address == reinterpret_cast<void*>(0x7ffc777fa461))
        std::print("");
  */
    switch (results[*analysis_address]) {
        case none:
            if (*analysis_address == 0xCC)
                if (*reinterpret_cast<const DWORD*>(analysis_address) == 0xCCCCCCCC)
                    return reached_end_of_function;
            return *analysis_address == opcodes::RETURN || *analysis_address == opcodes::RETURN_FAR || *reinterpret_cast<const WORD*>(analysis_address) == 0xe0ff ? reached_end_of_function : success;

        case has_mod_rm:
            return analyseModRM(analysis_address);

        case has_mod_rm | prefix:
            return analyseSpecialGroup(analysis_address);

        case has_mod_rm | special:
            return analyseGroup3(analysis_address);

        case has_mod_rm | special | prefix:
            return analyseAVX(analysis_address);

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

        case has_mod_rm | imm_two_bytes | imm_four_bytes:
            if (!increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD))
                return instruction_overflow;
            return analyseModRM(analysis_address);

        case has_mod_rm | imm_eight_bytes | imm_four_bytes:
            std::println("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})", reinterpret_cast<const void*>(analysis_address));
            return wrong_input;

        case imm_one_byte:
            return incrementLength() ? success : instruction_overflow;

        case imm_two_bytes:
            return increaseLength(SIZE_OF_WORD)  ? success : instruction_overflow;

        case imm_four_bytes:
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case imm_eight_bytes:
            return increaseLength(SIZE_OF_QWORD) ? success : instruction_overflow;

        case imm_one_byte | imm_two_bytes:
            return increaseLength(SIZE_OF_WORD + SIZE_OF_BYTE) ? success : instruction_overflow;

        case imm_two_bytes | imm_four_bytes | imm_eight_bytes:
            if (shortened)
                return increaseLength(SIZE_OF_WORD) ? success : instruction_overflow;

            if (rex_w)
                return increaseLength(SIZE_OF_QWORD) ? success : instruction_overflow;
            
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case imm_four_bytes | imm_eight_bytes:
            if (*analysis_address == opcodes::CALL || *analysis_address == opcodes::JUMP)
                setRipRelative();
            return increaseLength(rex_w ? SIZE_OF_QWORD : SIZE_OF_DWORD) ? success :instruction_overflow;

        case prefix:
            if ((*analysis_address & prefixes::REX_MASK) == prefixes::REX_BASE)
                rex_w = true;
            else if (!prefix_count && *analysis_address == prefixes::SHORT)
                shortened = true;
            if (!incrementPrefixCount()) 
                return prefix_overflow;
            if (!incrementLength()) 
                return instruction_overflow;
            return map(analysis_address + 1);
        
        default:
            std::println("[?] WTH Is Going On?");
            return wrong_input;
    }
}

Context::Status Context::analyseModRM(const BYTE* const preceding_byte_ptr) { using namespace mod_rm;
    if (!preceding_byte_ptr) 
        return no_input;
    if (!incrementOpcode())  
        return opcode_overflow;
    
    if (!incrementLength())  
        return instruction_overflow;
    
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case MOD11:
            return success;

        case MOD10:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case MOD01:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            return incrementLength() ? success : instruction_overflow;

        default:
            if ((preceding_byte_ptr[1] & RM_MASK) == 4) {
                has_SIB = true;
                return increaseLength(analyseSibBase(preceding_byte_ptr) ? SIZE_OF_BYTE + SIZE_OF_DWORD : SIZE_OF_BYTE) ? success : instruction_overflow;
            }
            if ((preceding_byte_ptr[1] & RM_MASK) != 5) 
                return success;
            rip_relative = true;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
    }
}

Context::Status Context::analyseAVX(const BYTE * const analysis_address) {
    if (!incrementLength())
        return instruction_overflow;

    if (!incrementPrefixCount())
        return prefix_overflow;
/*
    if (analysis_address == reinterpret_cast<void*>(0x7ffc777fa382))
        std::print("");
        */
    switch (*analysis_address){
        case 0xC5: 
            return analyseLDS(analysis_address + 1);
    
        case 0xC4:
            return analyseLES(analysis_address + 1);
    
        case 0x62:
            return analyseEVEX(analysis_address + 1);
        default:
            return wrong_input;
    }
}

Context::Status Context::analyseLDS(const BYTE* const preceding_byte_ptr) {
    if (!incrementOpcode())
        return opcode_overflow;

    if (!incrementLength())
        return instruction_overflow;
    if (preceding_byte_ptr == reinterpret_cast<void*>(0x7ffc777fa57b))
        std::print("");

    switch (preceding_byte_ptr[1]) {
        case 0x77:
            return success;
        
        case 0x70: case 0x71: case 0x72: case 0x73: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
            if (!incrementLength())
                return instruction_overflow;
            break;

        default:
            break;
    }
    return analyseModRM(preceding_byte_ptr + 1);
}


Context::Status Context::analyseLES(const BYTE* const preceding_byte_ptr) { using namespace AVX;
    if (!incrementOpcode())
        return opcode_overflow;

    if (!increaseLength(SIZE_OF_WORD))
        return instruction_overflow;

    switch (*preceding_byte_ptr & MMMM_MASK) { using enum Maps;
        case map0x0F38:
            return analyseModRM(preceding_byte_ptr + 2);

        case map0x0F3A:
            if (!incrementLength())
                return instruction_overflow;

            return analyseModRM(preceding_byte_ptr + 2);

        case map0x0F:
            switch (preceding_byte_ptr[2]) {
                case 0x70: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                    if (!incrementLength())
                        return instruction_overflow;
                    break;
                
                default:
                    break;
            }
            return analyseModRM(preceding_byte_ptr + 2);
        
        case wrong:
        default:
            return wrong_input;
    }
}


Context::Status Context::analyseEVEX(const BYTE* preceding_byte_ptr) {
    if (!preceding_byte_ptr)
        return  no_input;
    
    if (!incrementPrefixCount() || !incrementPrefixCount() || !incrementPrefixCount())
        return prefix_overflow;

    /*
    if (preceding_byte_ptr == reinterpret_cast<void*>(0x7ffc777fa37d))
        std::print("");
        */
    if (!increaseLength(SIZE_OF_WORD + 1))
        return instruction_overflow;

    switch (*preceding_byte_ptr & AVX::MM_MASK) { using enum AVX::Maps;
        case map0x0F3A:
            if (!incrementLength())
                return instruction_overflow;

            return analyseModRM(preceding_byte_ptr + 3);
        
        case map0x0F38:
            return analyseModRM(preceding_byte_ptr + 3);
        
        case map0x0F:

            switch (preceding_byte_ptr[3]) {
                case 0x70: case 0xC2: case 0xC4: case 0xC5: case 0xC6:
                    if (!incrementLength())
                        return instruction_overflow;
                    break;

                default:
                    break;
            }
            return analyseModRM(preceding_byte_ptr + 3);
        
        default:
            return wrong_input;
    }

}

Context::Status Context::analyseSpecialGroup(const BYTE* const preceding_byte_ptr) {
    if (!preceding_byte_ptr) 
        return no_input;
    
    if (!incrementLength())
        return instruction_overflow;
    
    if (!incrementOpcode())
        return opcode_overflow;
    BYTE idx = 1;
    switch (preceding_byte_ptr[idx]) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
        case 0x30: case 0x31: case 0x32: case 0x34: case 0x35:
        case 0x77: case 0xA2: case 0x0B: case 0xC8: case 0xC9:
        case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCF:
            return success;

        case 0x38:
            idx++;
            if (!incrementLength())
                return instruction_overflow;
            break;
        
        case 0x3A:
            if (!incrementLength())
                return instruction_overflow;
            idx++;
        case 0x70: case 0x71: case 0x72: case 0x73: 
        case 0xA4: case 0xBA: case 0xC4: case 0xC5: case 0xC6:
            if (!incrementOpcode())
                return opcode_overflow;
            if (!incrementLength())
                return instruction_overflow;
            break;

        default:
            if ((preceding_byte_ptr[idx] & 0xF0) != 0x80)
                break;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
    }
    return analyseModRM(idx + preceding_byte_ptr);
}

Context::Status Context::analyseGroup3(const BYTE* const analysis_address) {
    if (!incrementLength())
        return instruction_overflow;
    
    if (!incrementPrefixCount())
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

Context::Status Context::analyseF6(const BYTE* const preceding_byte_ptr) { using namespace mod_rm;
/*
    if (preceding_byte_ptr == reinterpret_cast<BYTE*>(0x7ff9e083dcc1))
        std::print("");
*/
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case MOD11:
            return analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE);

        case MOD10:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            if (success != analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;

        case MOD01:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            if (success != analyseRegBits(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            return incrementLength() ? success : instruction_overflow;

        default:
            if (!incrementLength())
                return instruction_overflow;
            if (success != analyseRM4nSIB(preceding_byte_ptr, SIZE_OF_BYTE, SIZE_OF_DWORD))
                return instruction_overflow;
            if ((preceding_byte_ptr[1] & RM_MASK) != 5) 
                return success;
            setRipRelative();
            return increaseLength(SIZE_OF_DWORD) ? success : instruction_overflow;
    }
}

Context::Status Context::analyseF7(const BYTE* const preceding_byte_ptr) { using namespace mod_rm;
   /* 
     if (reinterpret_cast<QWORD>(preceding_byte_ptr) == 0x7ffc778453cA)
        std::print("");
     */
    switch (preceding_byte_ptr[1] & MOD_MASK) {
        case MOD11:
            return analyseRegBits(preceding_byte_ptr,shortened ? SIZE_OF_WORD : SIZE_OF_DWORD);

        case MOD10:
            if (!increaseLength(SIZE_OF_DWORD))
                return instruction_overflow;
            if (success != analyseRM4nSIB(preceding_byte_ptr, SIZE_OF_BYTE, SIZE_OF_DWORD))
                return instruction_overflow;
            if ((preceding_byte_ptr[1] & REG_MASK) < 0x10)
                return increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD) ? success : instruction_overflow;
            return success;

        case MOD01:
            if (!incrementLength())
                return instruction_overflow;
            
            if (success != analyseRM4nSIB(preceding_byte_ptr, SIZE_OF_BYTE, SIZE_OF_DWORD))
                if (!incrementLength())
                    return instruction_overflow;
 
            if ((preceding_byte_ptr[1] & REG_MASK) >= 0x10) 
                return success;
            
            
            return increaseLength(shortened ? SIZE_OF_WORD : SIZE_OF_DWORD) ? success : instruction_overflow;

        default:
            if (success != analyseRM4(preceding_byte_ptr, SIZE_OF_BYTE))
                return instruction_overflow;
            if ((preceding_byte_ptr[1] & RM_MASK) == 5)
                if (!increaseLength(SIZE_OF_DWORD) )
                    return instruction_overflow;
                
        return analyseRegBits(preceding_byte_ptr, SIZE_OF_DWORD);
    }
}

WORD Context::analyseOpcodeType(const BYTE * const analysis_address) { using namespace opcodes;
    if (!analysis_address)
        return no_input;
/*
    if (analysis_address == reinterpret_cast<void*>(0x00007ff9e08a7119))
        std::print("");
*/
    switch (*analysis_address) {
        case RETURN_FAR:
            return ret | _far;

        case RETURN:
            return ret;

        case CALL:
            rip_relative = true;
            return call;

        case JUMP:
            if (prefix_count || opcode_length > 1)
                return unknown;
            rip_relative = true;
            return jump;

        case SHORT_JUMP:
            rip_relative = true;
            return jump | _short;

        case 0x0F:
            switch (analysis_address[1]) {
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
                    return (analysis_address[1] & 0xF0) == 0x80 ? conditional | _far | jump : unknown;
            }

        case 0xFF:
            rip_relative = true;
            if ((analysis_address[1] & 0xFC) == 0xE0 && analysis_address[-1] != 0xf7) {
                return indirect_reg_jump;
            }
            switch ((analysis_address[1] & mod_rm::REG_MASK) >> 3) {
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
            if (*analysis_address == 0xCC)
                if (*reinterpret_cast<const DWORD*>(analysis_address) == 0xCCCCCCCC)
                    return ret;
            if ((*analysis_address & 0xF0) == 0x70) {
                rip_relative = true;
                return conditional | jump;
            }
        return unknown;
    }
}

const BYTE * Context::resolveJump(const BYTE* const analysis_address) { using enum opcodes::Types;
    if (!analysis_address)
        return nullptr;
/*    
    if (analysis_address == reinterpret_cast<BYTE*>(0x00007FF9DDCAAEEA))
        std::print("");
*/
    switch (analyseOpcodeType(analysis_address + prefix_count)) {
        case conditional | _far | jump:
        case jump:
        case call: {
            auto addr = reinterpret_cast<const int* const>(analysis_address + getPreDisposition());
            int disposition = *addr;
            return analysis_address + length + *reinterpret_cast<const int* const>(analysis_address + getPreDisposition());
        }
        case jump | _short:
        case jump | conditional:
            return analysis_address + length + *reinterpret_cast<const signed char* const>(analysis_address + getPreDisposition());


        case jump | conditional | indirect:
        case indirect_call:
        case indirect_jump:
            return *reinterpret_cast<const BYTE * const *>(analysis_address + length + *reinterpret_cast<const int * const>(analysis_address + getPreDisposition()));

        default:
            return nullptr;
    }
}

block::TraceResults Context::checkForNewBlock(const BYTE* analysis_address) { using enum block::TraceResults;
    if (!analysis_address)
        return failed;
    
    switch (analyseOpcodeType(analysis_address + prefix_count)) { using enum opcodes::Types;

        case conditional | _far | jump:
        case conditional |  jump:
            return reachedConditionalJump;

        case jump:
        case _short | jump:
        case indirect_jump:
        case indirect_far_jump:
            return reachedJump;

        case call:

        case indirect_far_call:
            return reachedCall;

        case ret:
        case ret | _far:
            return reachedReturn;
        case indirect_call:
        case indirect_reg_jump:
            return reachedRegJump;


        default:
            return noNewBlock;
    }
}

void Context::log(const BYTE *instruction_head, DWORD idx) const {
    std::print("#{:3d} @{:p} ", idx, reinterpret_cast<const void*>(instruction_head));
    for (BYTE i = 0, instruction_length = length; i < instruction_length; i++)
        std::print("{:#04x} ", instruction_head[i]);
    std::println();
}