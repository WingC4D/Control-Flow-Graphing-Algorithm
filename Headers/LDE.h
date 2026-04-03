#pragma once
#include <Windows.h>
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
		constexpr DWORD TWO_GIGABYTES = 0x80000000;
		#define hUINT
		#define TRAMPOLINE_SIZE 0x0D
		#define MAX_INSTRUCTION_SIZE 0x0F
	#endif
#endif

enum IsNewBranch: BYTE;
struct FunctionTree;
struct Block;
struct CONDITIONAL_BRANCH;
constexpr BYTE SIZE_OF_BYTE					 = 0x01,
               SIZE_OF_WORD					 = 0x02,
               SIZE_OF_DWORD				 = 0x04,
			   RELATIVE_TRAMPOLINE_SIZE		 = 0x05,
               SIZE_OF_QWORD				 = 0x08,
               SIZE_OF_OWORD				 = 0x10,
               REX_MASK						 = 0x40,
               RIP_RELATIVE_MASK			 = 0x80,
               MOD_MASK						 = 0xC0,
               REG_MASK						 = 0x38,
               RM_MASK						 = 0x07,
               IMM16_MASK					 = 0x10,
               IMM32_MASK					 = 0x20,
               CALLS_MASK					 = 0x40,
               CONDITIONALS_MASK			 = 0x80,
               DISPOSITIONS_MASK			 = 0x30,
               ROOT_BRANCH_INSTRUCTION_COUNT = 0xA0;



enum Register: BYTE {
	ax, bx, cx, dx,sp, bp, si, di
};

enum LdeErrorCodes: BYTE {
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

struct LdeHookingState {
	LPVOID			functionAddress;
	LdeErrorCodes   status				   = success;
	BYTE			currInstructionContext = 0,
					instructionCount	   = 0,
					ripIndexesCount		   = 0,
					contextsArray[RELATIVE_TRAMPOLINE_SIZE]{ },
					prefixCountArray[RELATIVE_TRAMPOLINE_SIZE]{ },
					ripRelativeIndexesArray[RELATIVE_TRAMPOLINE_SIZE]{ };
	BYTE getCurrentPrefixCount() const {
		return static_cast<unsigned char>(prefixCountArray[instructionCount] & 0x0F);
	}
	LdeHookingState(LPVOID target_address): functionAddress(target_address) {
	}
};

struct LdeState {
	LdeErrorCodes    status;
	BYTE			 currInstructionContext,
					 instructionCount,
					 newBlocksCount;
	std::vector<BYTE>contextsArray,
					 prefixCountArray;
	LdeState():
	contextsArray(ROOT_BRANCH_INSTRUCTION_COUNT),
	prefixCountArray(ROOT_BRANCH_INSTRUCTION_COUNT) {
		status				   = success;
		currInstructionContext = 0;
		instructionCount	   = 0;
		newBlocksCount		   = 0;
	}
	BYTE getCurrentPrefixCount() const {
		return static_cast<unsigned char>(prefixCountArray[instructionCount] & 0x0F);
	}
};

struct LdeJumpResolutionState {
	LPVOID			lpFuncAddr;
	LdeErrorCodes   status					= success;
	BYTE			currInstructionContext	= 0,
					instructionCount		= 0,
					cb_count_of_rip_indexes = 0,
					contextsArray[1]{},
					prefixCountArray[1]{},
					rip_relative_indexes[1]{};
	
	LdeJumpResolutionState(LPVOID lpTarget): lpFuncAddr(lpTarget) {}

	BYTE getCurrentPrefixCount() const {
		return static_cast<unsigned char>(prefixCountArray[instructionCount] & 0x0F);
	}
};

enum state: BYTE {
	success_,
	reached_nt_dll,
	branch_is_obfuscated
};

class Lde { friend FunctionTree; friend  Block;

	static BYTE getValidInstructionsSizeHook(_Inout_ LPVOID& target_address, _Out_ LdeHookingState& State);

	static BOOLEAN findAndFixRelocations(_Inout_ LPBYTE gateway_trampoline_ptr, _In_ LPVOID target_function_ptr, _In_  LdeHookingState& State);

	static LPBYTE resolveJump(_In_ LPBYTE to_resolve_address);

	static IsNewBranch checkForNewBlock(LdeState& state, LPBYTE lpReference);

	inline static BYTE getInstructionLengthCtx(_In_ BYTE CandidateContext);

	[[nodiscard]] static BYTE mapInstructionLength(_In_ LPVOID analysis_address, _Inout_ BYTE& InstructionContext, _Inout_ LdeErrorCodes& status, _Inout_ BYTE& prefix_count);

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

	static void logInstructionAndAddressCtx(_In_ LPBYTE reference_address, _In_ BYTE CandidateContext, BYTE instruction_index);

	inline static void incrementOpcodeLenCtx(_Inout_ BYTE& CandidateContext, _Inout_ LdeErrorCodes& Status);

	inline static void setCurrentInstructionLength(_In_ BYTE instruction_length, _Inout_ BYTE& CandidateContext);

	inline static void resetHookingContexts(_Inout_ LdeHookingState& State);

	inline static void set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx);

	inline static void setContextRipRel(_Inout_ BYTE& CandidateContext);

	inline static void incrementInstructionLen(_Inout_ BYTE& CandidateContext, _Inout_ LdeErrorCodes& Status);

	inline static BYTE getOpcodeLenCtx(_In_ BYTE CandidateContext);

	static BOOLEAN traceIntoIAT(LdeHookingState& state);

	static inline BOOLEAN isCurrentInstructionShortened(BYTE prefix_count, LPBYTE reference_address);

	inline static BOOLEAN analyseSibBase(_In_ BYTE candidate);

	inline static BOOLEAN isRexCtx(_In_ BYTE CandidateContext);

	inline static BOOLEAN isRipRelativeCtx(_In_ BYTE CandidateContext);

	static BYTE getIndexInstructionLength(_In_ BYTE index, _Inout_ const LdeHookingState& State);

	static BYTE get_index_opcode_len(_In_ BYTE index, _In_ const LdeHookingState& State);
	
	static void logInstructionAndAddress(_In_ LPBYTE reference_address, _In_ BYTE InstructionContext);

	template<typename STATE>
	static void log_2(_In_ BYTE instruction_count, _In_ STATE& State);

	static void log_1(_In_ LPBYTE reference_address, _In_ const LdeHookingState& State);

	static BYTE analyse_special_group(_In_ LPBYTE candidate_address, _Inout_ BYTE& InstructionContext, _Inout_ LdeErrorCodes& status);

	static BYTE analyse_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ BYTE& InstructionContext, _Inout_ LdeErrorCodes& status) {
		BYTE cbRM				 = *lpCandidate & RM_MASK,
			 cbReg				 = *lpCandidate & REG_MASK,
		     cbMod				 = *lpCandidate & MOD_MASK,
			 added_opcode_length = 0;
		status = success;
		if (!lpCandidate) {
			status = no_input;
			return 0;
		}
		switch (cbMod) {
			case 0xC0: {
				break;
			}
			case 0x80: {
				added_opcode_length += SIZE_OF_DWORD;
				if (cbRM == 4) {
					added_opcode_length++;
					if (getOpcodeLenCtx(InstructionContext) < SIZE_OF_DWORD) {
						incrementOpcodeLenCtx(InstructionContext, status);
					}
					break;
				}
				if (cbReg < 0x10) {
					added_opcode_length++;
				}
				break;
			}
			case 0x40: {
				added_opcode_length++;
				if (cbRM == 4) {
					incrementOpcodeLenCtx(InstructionContext, status);
					added_opcode_length++;
				}
				break;
			}
			default: {
				if (cbRM == 4) {
					added_opcode_length++;
					if (getOpcodeLenCtx(InstructionContext) < 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
					}
					if (analyseSibBase(*(lpCandidate + SIZE_OF_BYTE))) {
						added_opcode_length += SIZE_OF_DWORD;
					}
					break;
				}
				if (cbRM == 5) {
					setContextRipRel(InstructionContext);
					added_opcode_length += SIZE_OF_DWORD;
					break;
				}
				break;
			}
		}
		return added_opcode_length;
	}

	static BYTE analyse_group3_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ BYTE& InstructionContext, LdeErrorCodes& status, BYTE prefix_count) {
		if (!*lpCandidate) {
			status = no_input;
			return 0;
		}
		status						= success;
		BYTE reg_bits				= *(lpCandidate + SIZE_OF_BYTE) & REG_MASK,
			 rm_bits				= *(lpCandidate + SIZE_OF_BYTE) & RM_MASK,
			 mod_bits				= *(lpCandidate + SIZE_OF_BYTE) & MOD_MASK,
			 added_opcode_length	= 0,
			 added_immediate_length	= 0;
		switch (*lpCandidate) {
			case 0xF6: {
				switch(mod_bits) {
					case 0xC0: {
						if (0x10 > reg_bits) {
							added_immediate_length++;
						}
						break;
					}
					case 0x80: {
						added_immediate_length ++;
						if (rm_bits == 4) {
							incrementOpcodeLenCtx(InstructionContext, status);
							added_opcode_length += SIZE_OF_DWORD;
						}
						if (0x10 > reg_bits) {
							added_immediate_length++;
						}
						break;
					}
					case 0x40: {
						added_immediate_length++;
						if (rm_bits == 4) {
							incrementOpcodeLenCtx(InstructionContext, status);
							added_opcode_length++;
						}
						if (0x10 > reg_bits) {
							added_immediate_length++;
						}
						break;
					}
					default: {
						if (rm_bits == 4) {
							incrementOpcodeLenCtx(InstructionContext, status);
							added_opcode_length++;
							if (analyseSibBase(*(lpCandidate + 2))) {
								added_immediate_length += SIZE_OF_DWORD;
							}
							break;
						}
						if (rm_bits == 5) {
							setContextRipRel(InstructionContext);
							added_opcode_length++;
						}
						break;
					}
				}
				break;
			}
			case 0xF7: {
				switch (mod_bits) {
					case 0xC0: {
						if (0x10 > reg_bits) {
							added_immediate_length++;
						}
						break;
					}
					case 0x80: {
						added_immediate_length += SIZE_OF_DWORD;
						if (rm_bits == 4) {
							incrementOpcodeLenCtx(InstructionContext, status);
							added_opcode_length++;
							if (analyseSibBase(*(lpCandidate + SIZE_OF_WORD))) {
								added_immediate_length += SIZE_OF_DWORD;
							}
						}
						if (0x10 > reg_bits) {
							added_immediate_length += analyse_reg_size_0xF7(lpCandidate, status, prefix_count);
						}
						break;
					}
					case 0x40: {
						if (rm_bits == 4) {
							incrementOpcodeLenCtx(InstructionContext, status);
							added_opcode_length++;
							break;
						}
						if (0x10 > reg_bits) {
							added_immediate_length += analyse_reg_size_0xF7(lpCandidate, status, prefix_count);
						}
						break;
					}
					default: {
						if (!reg_bits) {
							added_immediate_length += SIZE_OF_DWORD;
						}
						break;
					}
				}
				break;
			}
			default: {
				status = wrong_input;
				return 0;
			}
		}
		return added_opcode_length + added_immediate_length;
	}

	static BYTE analyse_reg_size_0xF7(_In_ LPBYTE candidate_address, _Inout_ LdeErrorCodes& status, _In_ BYTE prefix_count) {
		if (!candidate_address) {
			status = no_input;
			return 0;
		}
		status = success;
		if (isCurrentInstructionShortened(prefix_count, candidate_address)) {
			return SIZE_OF_WORD;
		}
		return SIZE_OF_DWORD;
	}
	
	static WORD analyseOpcodeType(_In_ LPBYTE candidate_addr, _Inout_ BYTE& InstructionContext);

	static LPBYTE analyseRedirectingInstruction(_In_ DWORD accumulated_length, _Inout_ LdeHookingState& State);

	template<typename STATE>
	static void prepareForNextStep(STATE& state){
		state.contextsArray[state.instructionCount] = state.currInstructionContext;
		state.currInstructionContext				= 0;
		state.instructionCount					   += 1;
	}

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