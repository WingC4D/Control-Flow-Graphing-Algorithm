#pragma once
#include <Windows.h>
#include "Context.h"
#include "FunctionTree.h"
#ifndef hUINT
	#ifdef _M_IX86
		typedef unsigned long	   hUINT
		#define L_UINT
		#define TRAMPOLINE_SIZE 0x100
	#elifdef _M_X64
		typedef unsigned long long L_UINT;
		constexpr DWORD TWO_GIGABYTES = 0x80000000;
		#define   hUINT
	#endif
#endif


struct FunctionTree;
struct Block;
interface LdeCommon;
constexpr BYTE SIZE_OF_BYTE				= 0x01,
               SIZE_OF_WORD				= 0x02,
               SIZE_OF_DWORD			= 0x04,
			   RELATIVE_TRAMPOLINE_SIZE	= 0x05,
               SIZE_OF_QWORD			= 0x08,
               TRAMPOLINE_SIZE          = 0x0D,
               MAX_PREFIX_COUNT         = 0x0E,
               SIZE_OF_OWORD			= 0x10,
			   MAX_INSTRUCTION_SIZE		= 0x0F,
			   REX_MASK					= 0x40,
               RIP_RELATIVE_MASK		= 0x80,
               MOD_MASK					= 0xC0,
               REG_MASK					= 0x38,
               RM_MASK					= 0x07,
               IMM16_MASK				= 0x10,
               IMM32_MASK				= 0x20,
               CALLS_MASK				= 0x40,
               CONDITIONALS_MASK		= 0x80,
               DISPOSITIONS_MASK		= 0x30,
               BLOCK_MAX_INSTRUCTIONS	= 0xA0;


enum Register: BYTE {
	ax, bx, cx, dx,sp, bp, si, di
};
/*
enum LdeStatus: BYTE {
	success,
	no_input,
	wrong_input,
	reached_end_of_function,
	reached_end_of_branch,
	reached_uninitialized_memory

};
*/
namespace opcodes {
	constexpr BYTE RETURN = 0xC3,
				   JUMP	  = 0xE9,
				   CALL	  = 0xE8;
}


namespace blk {
    enum TraceResults : BYTE;
}


struct LdeCommon { using enum inst::Context::Status;
    inst::Context         currContext{};
	inst::Context::Status status            = success;
	BYTE                  instruction_count = 0;
    DWORD                 size              = 0;
};

struct LdeHookingState: LdeCommon {
	const BYTE*   functionAddress;
	BYTE		  rip_indexes_count = 0,
				  ripRelativeIndexesArray[RELATIVE_TRAMPOLINE_SIZE]{};
	inst::Context contextsArray[RELATIVE_TRAMPOLINE_SIZE]{};

	LdeHookingState(const BYTE *target_address): functionAddress(target_address) {}
	
	void prepareForNextStep() {
		contextsArray[instruction_count] = currContext;
		currContext.clear();
		instruction_count++;
	}

	void reset() {
		for (BYTE i = 0; i < instruction_count; i++) 
			contextsArray[i].clear();

		for (BYTE i = 0; i < rip_indexes_count; i++)
			ripRelativeIndexesArray[i] = 0;

		currContext.clear();
		rip_indexes_count = 0;
		instruction_count = 0;
	}
};

struct LdeState: LdeCommon {
	std::vector<inst::Context> contextsArray;

	LdeState(): contextsArray(BLOCK_MAX_INSTRUCTIONS) {}

	void prepareNextStep() {
        size += currContext.getLength();
        contextsArray[instruction_count] = currContext;
        currContext.clear();
        instruction_count++;
	}

    void handleEnfOfTrace() {
        prepareNextStep();
        contextsArray.resize(instruction_count);
	}

    blk::TraceResults traceBlock(const BYTE* block_root, std::vector<const BYTE *>& NewFunctionsVec);

    DWORD getLastInstHeadOffset() {
        return size - (--contextsArray.end())->getLength();
    }
};

struct LdeJumpResolutionState: LdeCommon {
	LPVOID toResolve;
	inst::Context contextsArray[1]{};

	LdeJumpResolutionState(LPVOID lpTarget): toResolve(lpTarget) {}

	BYTE getCurrentPrefixCount() const {
		return currContext.getPrefixCount();
	}

	void prepareForNextStep() {
		contextsArray[0] = currContext;
		currContext		 = inst::Context{};
		instruction_count = 1;
	}
};

enum state: BYTE {
	success_,
	reached_nt_dll,
	branch_is_obfuscated
};

namespace blk {
    enum TraceResults : BYTE;
}

class Lde {
    friend FunctionTree; friend  Block; friend inst::Context; friend LdeState;

	static BYTE getValidInstructionsSizeHook(_Inout_ const void*& target_address, _Out_ LdeHookingState& State);

	static BOOLEAN findAndFixRelocations(_Inout_ LPBYTE trampoline_gateway_address, const LdeHookingState& State);

	static LPBYTE resolveJump(LPBYTE address_to_resolve) ;

	static blk::TraceResults checkForNewBlock(inst::Context& InstructionContext, const BYTE* lpReference);

	[[nodiscard]] static BYTE mapInstructionLength(const BYTE *analysis_address, inst::Context& InstructionContext, inst::Context::Status& status);

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

	static void logInstructionAndAddressCtx(const BYTE* reference_address, _In_ inst::Context CandidateContext, BYTE instruction_index);

	static BOOLEAN traceIntoIAT(LdeHookingState& State);

	static inline BOOLEAN isCurrentInstructionShortened(BYTE prefix_count, const BYTE* reference_address);

	inline static BOOLEAN analyseSibBase(_In_ BYTE candidate);

	static void logInstructionAndAddress(_In_ LPBYTE reference_address, _In_ inst::Context InstructionContext);

	template<typename STATE>
	static void log_2(_In_ BYTE instruction_count, _In_ STATE& State);

	static void log_1(_In_ const BYTE* reference_address, _In_ const LdeHookingState& State);

	static BYTE analyseSpecialGroup(_In_ const BYTE* candidate_address, _Inout_ inst::Context& InstructionContext, _Inout_ inst::Context::Status& status);

	static BYTE analyseModRm(_In_ const BYTE* preceding_byte_ptr, _Inout_ inst::Context& InstructionContext, _Inout_ inst::Context::Status& status);

	static BYTE analyseGroup3(_In_ const BYTE* lpCandidate, _Inout_ inst::Context& InstructionContext, _Out_ inst::Context::Status& status);

    static BYTE analyseRegSizeF7(_In_ const BYTE* candidate_address, _Inout_ inst::Context::Status& status, _In_ BYTE prefix_count) { using enum inst::Context::Status;
		if (!candidate_address) {
			status = no_input;
			return 0;
		}
		status = success;
		return isCurrentInstructionShortened(prefix_count, candidate_address) ? SIZE_OF_WORD : SIZE_OF_DWORD;
	}

	static WORD analyseOpcodeType(const BYTE* candidate_addr, _Inout_ inst::Context& InstructionContext);

	static const BYTE* analyseRedirectingInstruction(_In_ DWORD accumulated_length, _Inout_ LdeHookingState& State);

	enum instruction_types: WORD {
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
	static constexpr BYTE results[0x100] = {
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
		/*A*/imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, none, none, none, none, imm_one_byte, imm_eight_bytes | imm_four_bytes, none, none, none, none, none, none,
		/*B*/imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes,
		/*C*/has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, imm_two_bytes, none, has_mod_rm, has_mod_rm, has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, imm_two_bytes | imm_one_byte, none, imm_two_bytes, none, none, imm_one_byte, none, none,
		/*D*/has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		/*E*/imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, none, none, none, none, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, none, imm_one_byte, none, none, none, none,
		/*F*/prefix, none, prefix, prefix, none, none, has_mod_rm | special, has_mod_rm | special, none, none, none, none, none, none, has_mod_rm, has_mod_rm
	};
};