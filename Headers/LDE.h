#pragma once
#include <Windows.h>
#include <deque>
#include <iostream>
#include <format>
#include "FunctionTree.h"
#ifndef hUINT
	#define LOCAL_PROCESS_HANDLE reinterpret_cast<HANDLE>(-1)
	#define LOCAL_THREAD_HANDLE  reinterpret_cast<HANDLE>(-2)
	
	#define MAX_ITERATIONS 0x8000
	#define PAGE_SIZE	   0x10000
	#ifdef _M_IX86
		typedef unsigned long	   hUINT
		#define hkUINT
		#define TRAMPOLINE_SIZE 0x100
	#elifdef _M_X64
		typedef unsigned long long hkUINT;
		#define hUINT
		#define TRAMPOLINE_SIZE 0x0D
		#define MAX_INSTRUCTION_SIZE 0x0F
	#endif
#endif

struct FUNCTION_TREE;
struct BLOCK;
struct CONDITIONAL_BRANCH;
constexpr BYTE SIZE_OF_BYTE		 = 0x01,
               SIZE_OF_WORD		 = 0x02,
               SIZE_OF_DWORD	 = 0x04,
			   RELATIVE_TRAMPOLINE_SIZE = 0x05,
               SIZE_OF_QWORD	 = 0x08,
               SIZE_OF_OWORD	 = 0x10,
               REX_MASK			 = 0x40,
               RIP_RELATIVE_MASK = 0x80,
               MOD_MASK			 = 0xC0,
               REG_MASK			 = 0x38,
               RM_MASK			 = 0x07,
               IMM16_MASK		 = 0x10,
               IMM32_MASK		 = 0x20,
               CALLS_MASK		 = 0x40,
               CONDITIONALS_MASK = 0x80,
               DISPOSITIONS_MASK = 0x30,
               ROOT_BRANCH_INSTRUCTION_COUNT = 0xA0;

enum Register: BYTE {
	ax, bx, cx, dx,sp, bp, si, di
};

enum lde_error_codes: BYTE {
	success,
	no_input,
	wrong_input,
	reached_end_of_function,
	opcode_overflow,
	prefix_overflow,
	instruction_overflow,
	reached_end_of_branch

};

namespace opcodes {
	constexpr BYTE RETURN = 0xC3,
				   JUMP	  = 0xE9,
				   CALL	  = 0xE8;
}

struct LDE_HOOKING_STATE {
	LPVOID			lpFuncAddr;
	lde_error_codes ecStatus;
	BYTE			curr_instruction_ctx,
					instructionCount,
					cb_count_of_rip_indexes,
					contextsArray[RELATIVE_TRAMPOLINE_SIZE],
					prefixCountArray[RELATIVE_TRAMPOLINE_SIZE],
					rip_relative_indexes[RELATIVE_TRAMPOLINE_SIZE];
};

struct LDE_STATE {
	lde_error_codes ecStatus;
	BYTE			curr_instruction_ctx,
					instructionCount,
					cb_count_of_branches;
	std::deque<BYTE>contextsArray,
					prefixCountArray;
	LDE_STATE():
	contextsArray(ROOT_BRANCH_INSTRUCTION_COUNT),
	prefixCountArray(ROOT_BRANCH_INSTRUCTION_COUNT) {
		ecStatus				 = success;
		curr_instruction_ctx     = NULL;
		instructionCount = NULL;
		cb_count_of_branches	 = NULL;
	}
};

struct LDE_JUMP_RESOLUTION_STATE {
	LPVOID			lpFuncAddr;
	lde_error_codes ecStatus;
	BYTE			curr_instruction_ctx,
					instructionCount,
					cb_count_of_rip_indexes,
					contextsArray[1],
					prefixCountArray[1],
					rip_relative_indexes[1];
	};

	enum IS_NEW_BRANCH: unsigned char {
		no,
		no_reached_ret,
		yes_reached_conditional_branch,
		yes_reached_non_conditional_branch,
		yes_is_call,
		algorithm_failed
	};

	enum state : BYTE {
		success0,
		reached_nt_dll,
		branch_is_obfuscated
	};


class LDE {
public:
	friend FUNCTION_TREE; friend  BLOCK;

	static BYTE get_first_valid_instructions_size_hook(_Inout_ LPVOID* lpCodeBuffer, _Out_ LDE_HOOKING_STATE& state);

	static BOOLEAN find_n_fix_relocation(_Inout_ LPBYTE lpGateWayTrampoline, _In_ LPVOID lpTargetFunction, _In_  LDE_HOOKING_STATE& state);

	static LPBYTE ResolveJump(_In_ const LPBYTE& lpSartAddress);

	static IS_NEW_BRANCH checkForNewBlock(LDE_STATE& state, const LPBYTE& lpReference);

	inline static BYTE GetInstructionLenCtx(_In_ const BYTE& ucCurrentInstruction_ctx);

	template<typename STATE>
	static BYTE MapInstructionLen(_In_ const LPVOID& lpCodeBuffer, _Inout_ STATE& state) { using namespace std;
		if (!lpCodeBuffer) {
			state.ecStatus = no_input;
			return NULL;
		}
		if (*static_cast<LPBYTE>(lpCodeBuffer) == 0xCC) {
			//cout << format("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...\n", reinterpret_cast<DWORD64>(lpCodeBuffer));
			return NULL;
		}
		state.ecStatus = success;
		LPBYTE lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);
		increment_inst_len(state);
		switch (results[*lpReferenceBuffer]) {
		case none: {
			if (*lpReferenceBuffer == 0xC3 || *lpReferenceBuffer == 0xC2) { state.ecStatus = reached_end_of_function; }
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx), state);
			break;
		}
		case has_mod_rm: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | prefix: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_special_group(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | special: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_group3_mod_rm(lpReferenceBuffer, state), state);
			break;
		}
		case has_mod_rm | imm_one_byte: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + SIZE_OF_BYTE + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | imm_two_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + SIZE_OF_WORD + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | imm_four_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + SIZE_OF_DWORD + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | imm_eight_bytes: {
			increment_opcode_len(state);
			set_curr_inst_len(getCurrentPrefixCount(state) + SIZE_OF_QWORD + getOpcodeLenCtx(state.curr_instruction_ctx) + analyse_mod_rm(lpReferenceBuffer + 1, state), state);
			break;
		}
		case has_mod_rm | imm_eight_bytes | imm_four_bytes: {
			cout << "[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @" << format("{:#x})\n", *lpReferenceBuffer);
			break;
		}
		case imm_one_byte: {
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_BYTE, state);
			break;
		}
		case imm_two_bytes: {
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_WORD, state);
			break;
		}
		case imm_four_bytes: {
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
			break;
		}
		case imm_eight_bytes: {
			set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_QWORD, state);
			break;
		}
		case imm_four_bytes | imm_eight_bytes: {
			if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9) {
				SetCurrentContextRipRel(state.curr_instruction_ctx);
				if (!is_curr_instruction_shortened(getCurrentPrefixCount(state), lpReferenceBuffer)) {
					set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_DWORD, state);
				}
				else {
					set_curr_inst_len(getCurrentPrefixCount(state) + getOpcodeLenCtx(state.curr_instruction_ctx) + SIZE_OF_WORD, state);
				}
			}
			else if (is_curr_ctx_bREX_w(state)) {
				if (*(lpReferenceBuffer - (getOpcodeLenCtx(state.curr_instruction_ctx) - SIZE_OF_BYTE)) & 0x48) {
					set_curr_inst_len(getOpcodeLenCtx(state.curr_instruction_ctx) + getCurrentPrefixCount(state) + SIZE_OF_QWORD, state);
					break;
				}
			}
			set_curr_inst_len(getOpcodeLenCtx(state.curr_instruction_ctx) + getCurrentPrefixCount(state) + SIZE_OF_DWORD, state);
			break;
		}
		case prefix: {
			state.prefixCountArray[state.instructionCount] += 1;
			if (getCurrentPrefixCount(state) > 0x0E) {
				state.ecStatus = prefix_overflow;
				return NULL;
			}
			if ((results[*lpReferenceBuffer] & 0xF0) == 0x40) { set_curr_ctx_bRex_w(state.curr_instruction_ctx); }
			lpReferenceBuffer++;
			return MapInstructionLen(lpReferenceBuffer, state);
		}
		default: {
			state.ecStatus = wrong_input;
			cout << "[?] WTH Is Going On?\n";
			return NULL;
		}
		}
		return GetInstructionLenCtx(state.curr_instruction_ctx);
	}

	template<typename STATE>
	static BYTE getCurrentPrefixCount(STATE& state);

private:
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


	inline static BOOLEAN analyse_sib_base(_In_ BYTE cbCandidate);

	template<typename STATE>
	static BOOLEAN is_curr_ctx_bREX_w(_In_ const STATE& state);

	template<typename STATE>
	static BOOLEAN is_RIP_relative(const _In_ STATE& state);

	inline static BYTE getOpcodeLenCtx(_In_ const BYTE& ucCurrentInstruction_ctx);

	template<typename STATE>
	static BYTE get_index_ctx_inst_len(_In_ BYTE cbIndex, _Inout_ const STATE& state);

	template<typename STATE>
	static BYTE get_index_opcode_len(_In_ BYTE cbIndex, _In_ const STATE& state);

	template<typename STATE>
	static void increment_opcode_len(_Inout_ STATE& state);

	template<typename STATE>
	static void increment_inst_len(_Inout_ STATE& state);
	
	static void reset_hooking_contexts(_Inout_ LDE_HOOKING_STATE& state);

	inline static void set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx);

	inline static void SetCurrentContextRipRel(_Inout_ BYTE& ucCurrentInstructionCtx) ;

	template<typename STATE>
	static void set_curr_inst_len(_In_ BYTE cbInstructionLength, _Inout_ STATE& state) {
		using namespace std;
		if (cbInstructionLength > MAX_INSTRUCTION_SIZE) {
			cout << format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0x0F!\n[i] Received instruction length: {:#X}\n", static_cast<int>(cbInstructionLength));
			return;
		}
		state.curr_instruction_ctx &= 0xC3;
		state.curr_instruction_ctx |= cbInstructionLength << 2;
	}

	template<typename STATE>
	static void set_curr_opcode_len(_In_ BYTE cbOpcodeLength,_Inout_ STATE& state);

	template<typename STATE>
	static void logInstructionAndAddress(_In_ const LPBYTE& lpReferenceAddress, _In_ const STATE& state);

	static void logInstructionAndAddressCtx(_In_ const LPBYTE& lpReferenceAddress, _In_ const BYTE& state, const BYTE& cbInstructionIndex);

	template<typename STATE>
	static void log_2(_In_ const BYTE& cbInstructionCounter, _In_ STATE& lde_state);

	template<typename STATE>
	static void log_1(_In_ LPBYTE lpReferenceAddress, _In_ const STATE& state);

	template<typename STATE>
	static BYTE analyse_special_group(_In_ LPBYTE lpCandidate, _Inout_ STATE& state);

	template<typename STATE>
	static BYTE analyse_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ STATE& state);

	template<typename STATE>
	static BYTE analyse_group3_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ STATE& state);

	template<typename STATE>
	static BYTE analyse_reg_size_0xF7(_In_ LPBYTE lpCandidate, _In_ STATE& state);
	
	static WORD analyse_opcode_type(_In_ const LPBYTE& lpCandidate_addr, _Inout_ BYTE& ucInstructionContext_ref);

	template<typename STATE>
	static LPBYTE analyse_redirecting_instruction(_In_ DWORD cbAccumulatedLength, _Inout_ STATE& state);

	template<typename STATE>
	static BYTE get_index_prefix_count(const BYTE ucIndex, STATE& state);

	static inline BOOLEAN is_curr_instruction_shortened(const BYTE cbPrefixCount, LPBYTE lpReferenceAddress);

	template<typename STATE>
	static void prepareForNextStep(STATE& state){
		state.contextsArray[state.instructionCount] = state.curr_instruction_ctx;
		state.curr_instruction_ctx = NULL;
		state.instructionCount += 1;
	}
	

	static BOOLEAN cleanup_inner_branches(LDE_STATE& state, BLOCK& root_branch_ctx);

	static BOOLEAN traceIntoIAT(LDE_HOOKING_STATE& state);
	
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
protected:
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
		imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, imm_eight_bytes, none, none, none, none, imm_one_byte, imm_eight_bytes | imm_four_bytes, none, none, none, none, none, none,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes,
		has_mod_rm | imm_one_byte, has_mod_rm | imm_one_byte, imm_two_bytes, none, has_mod_rm, has_mod_rm, has_mod_rm | imm_one_byte, has_mod_rm | imm_four_bytes, imm_two_bytes | imm_one_byte, none, imm_two_bytes, none, none, imm_one_byte, none, none,
		has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm, has_mod_rm,
		imm_one_byte, imm_one_byte, imm_one_byte, imm_one_byte, none, none, none, none, imm_eight_bytes | imm_four_bytes, imm_eight_bytes | imm_four_bytes, none, imm_one_byte, none, none, none, none,
		prefix, none, prefix, prefix, none, none, has_mod_rm | special, has_mod_rm | special, none, none, none, none, none, none, has_mod_rm, has_mod_rm
	};
};