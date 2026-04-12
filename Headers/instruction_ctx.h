#pragma once
#include <print>
#ifndef WIN32
    typedef unsigned char  BYTE, *LPBYTE;
    typedef unsigned short WORD;
    typedef unsigned long  DWORD;
    typedef                BYTE BOOLEAN;
    typedef void           VOID,* LPVOID;
#endif
typedef unsigned long  long QWORD;

enum LdeStatus: BYTE;

namespace block {
    enum TraceResults: BYTE {
            noNewBlock,
            reachedReturn,
            reachedConditionalJump,
            reachedJump,
            reachedCall,
            failed
    };
    
}


namespace inst {
    constexpr BYTE SIZE_OF_BYTE  = 0x01,
                   SIZE_OF_WORD  = 0x02,
                   SIZE_OF_DWORD = 0x04,
                   SIZE_OF_QWORD = 0x08;


    enum first_byte_traits: BYTE {
		none		    = 0x00,
		has_mod_rm      = 0x01,
		special		    = 0x02,
		imm_control     = 0x04,
		prefix		    = 0x08,
		imm_one_byte    = 0x10,
		imm_two_bytes   = 0x20,
		imm_four_bytes  = 0x40,
		imm_eight_bytes = 0x80
	};

    namespace prefixes {
        constexpr BYTE REX_BASE = 0x48,
                       SHORT    = 0x66,
                       REX_MASK = 0xF8;
    }

    namespace opcodes {
        enum types: WORD {
	    	inc				  = 0x0000,
	    	dec				  = 0x0001,
	    	mov				  = 0x0002,
	    	call			  = 0x0003,
	    	jump			  = 0x0004,
	    	pop				  = 0x0005,
	    	push			  = 0x0006,
	    	lea				  = 0x0007,
	    	add				  = 0x0008,
	    	sub				  = 0x0009,
	    	mul				  = 0x000A,
	    	imul			  = 0x000B,
	    	div				  = 0x000C,
	    	idiv			  = 0x000D,
	    	ret				  = 0x000E,
	    	exchange		  = 0x000F,
	    	loop			  = 0x0010,
	    	_short			  = 0x0200,
	    	_near			  = 0x0400,
	    	_far			  = 0x0800,
	    	_sys			  = 0x1000,
	    	sys_exit		  = 0x1100,
	    	sys_enter		  = 0x1200,
	    	sys_call		  = 0x1002,
	    	sys_ret			  = 0x1400,
	    	conditional		  = 0x2000,
	    	indirect		  = 0x3007,
	    	indirect_inc	  = 0x3001,
	    	indirect_dec	  = 0x3002,
	    	indirect_call	  = 0x3003,
	    	indirect_far_call = 0x3803,
	    	indirect_jump	  = 0x3004,
	    	indirect_far_jump = 0x3804,
	    	indirect_push	  = 0x3005,
	    	indirect_invalid  = 0x3006,
	    	unknown			  = 0xFFFF
	    };

        constexpr BYTE CALL       = 0xE8,
                       JUMP       = 0xE9,
                       SHORT_JUMP = 0xEB,
                       RETURN_FAR = 0xC2,
                       RETURN     = 0xC3;
    }

    namespace mod_rm {
        constexpr BYTE RM_MASK  = 0x07,
                       REG_MASK = 0x38,
                       MOD_MASK = 0xC0,
                       MOD11    = 0xC0,
                       MOD10    = 0x80,
                       MOD01    = 0x40;

        enum Status: BYTE {
            success_stop,
            success_continue,
            failed
        };
    }

	constexpr BYTE MAX_OPCODE_SIZE = 0x04,
				   MAX_PREFIXES    = 0x0E,
				   MAX_SIZE        = 0x0F;

    inline BOOLEAN analyseSibBase(const BYTE* preceding_word_ptr) {
        return (preceding_word_ptr[2] & 0x07) == 5;
    }

    class Context {
    public:
        enum Status: BYTE {
            success,
            no_input,
            wrong_input,
            opcode_overflow,
            prefix_overflow,
            instruction_overflow,
            reached_end_of_function
        };

        const BYTE*          resolveJump(const BYTE* analysis_address);
        WORD                 analyseOpcodeType(const BYTE* analysis_address);
        [[nodiscard]] Status map(const BYTE* analysis_address);

        BOOLEAN isRexW() const {
            return rex_w;
        }

        BOOLEAN isRipRelative() const {
            return rip_relative;
        }

        BOOLEAN isShortened() const {
            return shortened;
        }

        BYTE getLength() const {
            return length; 
        }

        BYTE getPrefixCount() const {
            return prefix_count;
        }

        BYTE getOpcodeLength() const {
            return opcode_length + 1;
        }

        BYTE getDisposition() const {
            return length - getPreDisposition();
        }

        BYTE getPreDisposition() const {
            return prefix_count + getOpcodeLength();
        }

        BOOLEAN setLength(const BYTE new_length) {
            if (new_length > MAX_SIZE)
                return false;

            length = new_length;
            return true;
        }

        BOOLEAN incrementLength() {
            if (length == MAX_SIZE)
                return false;

            length++;
            return true;
        }

        BOOLEAN incrementPrefixCount() {
            if (prefix_count == MAX_PREFIXES)
                return false;

            prefix_count++;
            return true;
        }

        BOOLEAN incrementOpcode() {
            if (opcode_length == 3)
                return false;

            opcode_length++;
            return true;
        }

        BOOLEAN increaseLength(const BYTE to_add) {
            if (length + to_add > MAX_SIZE)
                return false;

            length += to_add;
            return true;
        }

        BOOLEAN setPrefixCount(const BYTE new_count) {
            if (new_count > MAX_PREFIXES)
                return false;

            prefix_count = new_count;
            return true;
        }

        void setRipRelative() {
            rip_relative = true;
        }

        void setRexW() {
            rex_w = true;
        }

        void clear() {
            *reinterpret_cast<WORD*>(this) = 0;
        }

        void log_addr_idx(const BYTE* instruction_head, DWORD idx) const;

        block::TraceResults checkForNewBlock(const BYTE* lpReference);

    private:
        WORD   opcode_length : 2 = 0,
               length        : 4 = 0,
               rex_w         : 1 = 0,
               rip_relative  : 1 = 0,
               prefix_count  : 4 = 0,
               has_SIB       : 1 = 0,
               shortened     : 1 = 0;

        Status analyseModRM(const BYTE* preceding_byte_ptr),
               analyseSpecialGroup(const BYTE* preceding_byte_ptr),
               analyseGroup3(const BYTE* analysis_address),
               analyseF6(const BYTE* preceding_byte_ptr),
               analyseF7(const BYTE* preceding_byte_ptr);

        Status analyseRM4(const BYTE* preceding_byte_ptr, const BYTE to_add) {
            if ((preceding_byte_ptr[1] & mod_rm::RM_MASK) != 4)  
                return success;
            has_SIB = true;
            return increaseLength(to_add) ? success : instruction_overflow;
        }

        Status analyseRM4nSIB(const BYTE* preceding_byte_ptr, const BYTE to_add, const BYTE to_add_sib) {
            if ((preceding_byte_ptr[1] & mod_rm::RM_MASK) != 4)
                return success;
            has_SIB = true;
            return increaseLength(analyseSibBase(preceding_byte_ptr) ? to_add + to_add_sib : to_add) ? success : instruction_overflow;
        }

        Status analyseRegBits(const BYTE* preceding_byte_ptr, const BYTE to_add) {
            if ((preceding_byte_ptr[1] & mod_rm::REG_MASK) < 0x10)
                return increaseLength(to_add) ? success : instruction_overflow;
            return success;
        }
        
    protected:
        WORD reserved : 2 = 0;
	};


    static BYTE results[256] {
        has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm | prefix,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm,
		has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, imm_one_byte, imm_four_bytes, has_mod_rm, has_mod_rm,
		prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix, prefix,
		none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
		none, none, prefix, has_mod_rm, prefix, prefix, prefix, prefix, imm_four_bytes, has_mod_rm | imm_eight_bytes | imm_four_bytes, imm_one_byte, has_mod_rm | imm_one_byte, none, none, none, none,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte,
		has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		none, none, none, none, none, none, none, none, none, none, none, none, none, none, none, none,
/*A*/   imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, none, none, none, none, imm_one_byte, imm_eight_bytes | imm_four_bytes, none, none, none, none, none, none,
/*B*/   imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes,
/*C*/   has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, imm_two_bytes, none, has_mod_rm, has_mod_rm, has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, imm_two_bytes | imm_one_byte, none, imm_two_bytes, none, none, imm_one_byte, none, none,
/*D*/   has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
/*E*/   imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, none, none, none, none, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, none, imm_one_byte, none, none, none, none,
/*F*/   prefix, none, prefix, prefix, none, none, has_mod_rm | special, has_mod_rm | special, none, none, none, none, none, none, has_mod_rm, has_mod_rm
    };
}