#include "LDE.h"

LPBYTE LDE::ResolveJump(_In_ const LPBYTE& lpSartAddress) {
	LDE_JUMP_RESOLUTION_STATE state = { .lpFuncAddr = lpSartAddress };

	if (!MapInstructionLen(state.lpFuncAddr, state)) {
		return nullptr;
	}
	state.contexts_arr[0] = state.curr_instruction_ctx;
	BYTE   ucInstructionLength	= GetInstructionLenCtx(state.curr_instruction_ctx),
		   ucOpcodeLength		= get_curr_opcode_len(state.curr_instruction_ctx),
		   cbPrefixCount		= get_current_prefix_count(state),
		   ucDispositionSize	= ucInstructionLength - cbPrefixCount - ucOpcodeLength;
	LPVOID lpResult,
		   lpDispositionAddress = lpSartAddress + ucInstructionLength - ucDispositionSize;
	switch (analyse_opcode_type(lpSartAddress, state.curr_instruction_ctx)) {
		case _short | jump:
		case _near | jump:
		case call:
		case jump:
		case conditional | jump | _short: {
			switch (ucDispositionSize) {
				case SIZE_OF_BYTE: {
					lpResult = lpSartAddress + *static_cast<signed char*>(lpDispositionAddress) + ucInstructionLength;
					break;
				}
				case SIZE_OF_DWORD: {
					lpResult = lpSartAddress + *static_cast<int*>(lpDispositionAddress) + ucInstructionLength;
					break;
				}
				default: {
					lpResult = nullptr;
					break;
				}
			}
			break;
		}
		case indirect_call:
		case indirect_far_jump:
		case indirect_jump:
		case indirect_far_call: {
			switch (ucDispositionSize) {
				case SIZE_OF_BYTE: {
					lpResult = *reinterpret_cast<LPVOID *>(lpSartAddress + *static_cast<signed char*>(lpDispositionAddress) + ucInstructionLength);
					break;
				}
				case SIZE_OF_DWORD: {
					lpResult = *reinterpret_cast<LPVOID *>(lpSartAddress + *static_cast<int*>(lpDispositionAddress) + ucInstructionLength);
					break;
				}
				default: {
					lpResult = nullptr;
					break;
				}
			}
			break;
		}
		default: {
			lpResult = nullptr;
			break;
		}
	}
	return static_cast<BYTE*>(lpResult);
}

BOOLEAN LDE::cleanup_inner_branches(LDE_STATE& state, BLOCK& root_branch_ctx) {
		  BYTE   cb_count_of_cleaned_indexes  = NULL;
	const LPBYTE lpReference				   = const_cast<LPBYTE>(root_branch_ctx.lpLandmarks->lpRoot);

		switch (state.prefix_count_arr[cb_count_of_cleaned_indexes] & (CONDITIONALS_MASK | DISPOSITIONS_MASK)) {
			case NULL: {
				break;
			}
			case CONDITIONALS_MASK: {
				BLOCK branch(lpReference, 0, 0,0);
				break;
			}
			case IMM16_MASK: { //TODO: Complete Word Resolutions If Needed.
				MapInstructionLen(const_cast<BYTE*>(root_branch_ctx.lpLandmarks->lpRoot), state);
				logInstructionAndAddress(static_cast<BYTE*>(root_branch_ctx.lpLandmarks->lpEnd), state);
				prepareForNextStep(state);//TODO: Find A Non Templated Place To Invoke This Function In LDE.cpp
				break;
			}

			case IMM32_MASK: {
				
				break;
			}
			default: { return wrong_input; }
		}
		return TRUE;
}

BYTE LDE::get_first_valid_instructions_size_hook(_Inout_ LPVOID *lpCodeBuffer, _Out_ LDE_HOOKING_STATE& state) {
	if (!lpCodeBuffer) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.lpFuncAddr		  = *lpCodeBuffer;
	BYTE *lpReference		  = static_cast<LPBYTE>(*lpCodeBuffer),
		  cbAccumulatedLength = MapInstructionLen(lpReference, state);
	if (!cbAccumulatedLength) {
		state.ecStatus = wrong_input;
		return NULL;
	}
	if (traceIntoIAT(state)) {
		reset_hooking_contexts(state);
		lpReference   = static_cast<LPBYTE>(state.lpFuncAddr);
		*lpCodeBuffer = lpReference;
		cbAccumulatedLength = NULL;
		if (!state.lpFuncAddr) {
			return NULL;
		}
	} else {
		prepareForNextStep(state);
		if (is_RIP_relative(state)) {
			state.rip_relative_indexes[state.cb_count_of_rip_indexes] = state.cb_count_of_instructions;
			state.cb_count_of_rip_indexes++;
		}
		lpReference += cbAccumulatedLength;
	}
	while (cbAccumulatedLength < RELATIVE_TRAMPOLINE_SIZE && state.ecStatus == success) {
		BYTE cbCurrentInstructionLength = MapInstructionLen(lpReference, state);
		if (!cbCurrentInstructionLength) {
			state.lpFuncAddr = analyse_redirecting_instruction(cbAccumulatedLength, state);
			reset_hooking_contexts(state);
			if (!state.lpFuncAddr) {
				return NULL;
			}
			lpReference			= static_cast<LPBYTE>(state.lpFuncAddr);
			*lpCodeBuffer		= lpReference;
			cbAccumulatedLength = NULL;
			continue;
		}
		if (*lpReference == opcodes::RETURN) { state.ecStatus = reached_end_of_function; break; }
		//log_1(lpReference, state);
		prepareForNextStep(state);
		if (is_RIP_relative(state)) {
			state.rip_relative_indexes[state.cb_count_of_rip_indexes] = state.cb_count_of_instructions;
			state.cb_count_of_rip_indexes++;
		}
		cbAccumulatedLength += cbCurrentInstructionLength;
		lpReference			+= cbCurrentInstructionLength;
	}
	//log_1(lpReference, state);	
	//log_2(cbInstructionCounter);
	if (state.ecStatus != success &&
		state.ecStatus != reached_end_of_function) {
		return NULL;
	}
	return cbAccumulatedLength;
}

template<typename STATE>
LPBYTE LDE::analyse_redirecting_instruction(_In_ DWORD cbAccumulatedLength, _Inout_ STATE& state) {using namespace std;
	if (!state.cb_count_of_instructions) {
		state.ecStatus = wrong_input;
		return nullptr;
	}
	BYTE	  ucLastValidIndex	  = state.cb_count_of_instructions - 1,
			  cbInstructionLength = get_index_ctx_inst_len(ucLastValidIndex, state),
			  cbOpcodeLength	  = get_index_opcode_len(ucLastValidIndex, state),
		      cbPrefixCount		  = get_index_prefix_count(ucLastValidIndex,state );
	LPBYTE	  lpReferenceAddress  = static_cast<LPBYTE>(state.lpFuncAddr) + cbAccumulatedLength - cbInstructionLength;
	LPVOID    lpDisposition		  = lpReferenceAddress + cbOpcodeLength + cbPrefixCount;
	switch (analyse_opcode_type(lpReferenceAddress, state.curr_instruction_ctx)) {
		case ret:
		case ret | _short:
		case ret | _near:
		case ret | _far:
		case ret | _near | _far:
		case ret | _short | _near:
		case ret | _far | _short:
		case ret | _near  | _short | _far: {
			state.ecStatus = reached_end_of_function;
			return lpReferenceAddress;
		}
		case jump:
		case call: {
			INT32 i32RVA;
			if (!is_curr_instruction_shortened(get_index_prefix_count(state.cb_count_of_instructions, state), lpReferenceAddress)) {
				i32RVA = *static_cast<PINT32>(lpDisposition);
			} else {
				i32RVA = *static_cast<PINT16>(lpDisposition);
			}
			return lpReferenceAddress + cbInstructionLength + i32RVA;
		}
		case indirect_call:
		case indirect_far_call:
		case indirect_jump:
		case indirect_far_jump: {
			switch (cbInstructionLength - cbOpcodeLength) {
				case SIZE_OF_BYTE: {
					BYTE cbRVA = cbInstructionLength;
					cbRVA += *static_cast<LPBYTE>(lpDisposition);
#ifdef DEBUG
					cout << format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + cbRVA);
				}
				case SIZE_OF_WORD: {
					WORD wRVA = cbInstructionLength;
					wRVA += *static_cast<PWORD>(lpDisposition);
#ifdef DEBUG
					cout << format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + wRVA);
				}
				case SIZE_OF_DWORD: {
					DWORD dwRVA = cbInstructionLength;
					dwRVA += *static_cast<PDWORD>(lpDisposition);
#ifdef DEBUG
					cout << format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + dwRVA);
				}
				case SIZE_OF_QWORD: {
					ULONGLONG ullRVA = cbInstructionLength;
					ullRVA += *static_cast<PULONGLONG>(lpDisposition);
#ifdef DEBUG
					cout << format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + ullRVA);
				}
				default: {
					state.ecStatus = wrong_input;
					return nullptr;
				}
			}
		}
		default: {
			state.ecStatus = wrong_input;
			return nullptr;
		}
	}
}

template<typename STATE>
void LDE::log_1(_In_ const LPBYTE lpReferenceAddress, _In_ const STATE& state) { using namespace std;
	BYTE cbAccumulatedLength	    = lpReferenceAddress - state.lpFuncAddr,
		 cbCurrentInstructionLength = get_context_instruction_length(state.curr_instruction_ctx),
		 cbCurrentPrefixCount		= get_current_prefix_count(state),
		 ucOpcodeLength				= get_curr_opcode_len(state.curr_instruction_ctx),
		 i;
	cout <<format(
		"[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}\n[i]",
		cbCurrentInstructionLength,
		cbAccumulatedLength,
		*lpReferenceAddress);
	
	if (cbCurrentPrefixCount) {
		cout << " Found Prefix Bytes: ";
		for (i = NULL; i < cbCurrentPrefixCount; i++) {
			cout << format("{:#4X} ", *(lpReferenceAddress + i));
		}
		cout << " | ";
	}
	if (ucOpcodeLength) {
		cout << "Found Opcode Bytes: ";
		for (i = cbCurrentPrefixCount; i < cbCurrentPrefixCount + ucOpcodeLength; i++) {
			cout << format("{:#X} ", *(lpReferenceAddress + i));
		}
	}
	if (get_context_instruction_length(state.curr_instruction_ctx) > ucOpcodeLength + cbCurrentPrefixCount) {
		cout << " | Found Operands Bytes: ";
		for (i = cbCurrentPrefixCount + ucOpcodeLength; i < cbCurrentInstructionLength; i++) {
			cout << format("{:#04X} ", *(lpReferenceAddress + i));
		}
	}
	cout << "\n\n";
}

template<typename STATE>
void LDE::log_2(const BYTE& cbInstructionCounter, _In_ STATE& lde_state) { using namespace std;
	cout << "[i] Held contexts: ";
	for (BYTE i = NULL; i < cbInstructionCounter; i++) {
		cout << format("{:#4X}, ", retinterpret_cast<BYTE>(lde_state.contexts_arr[i]));
	}
	cout << "\n";
}

template<typename STATE>
void LDE::logInstructionAndAddress(_In_ const LPBYTE& lpReferenceAddress, _In_ const STATE& state) {
	using namespace std;
	LPBYTE lpReferenceForPrint = lpReferenceAddress;
	cout << format("#{:2d} @{:P} ",state.cb_count_of_instructions, reinterpret_cast<LPVOID>(lpReferenceForPrint));
	BYTE cbInstructionLen = GetInstructionLenCtx(state.curr_instruction_ctx);
	for (BYTE i = NULL; i < cbInstructionLen; i++) {
		cout << format("{:#04X} ", static_cast<BYTE>(*(lpReferenceForPrint + i)));
	}
	cout << "\n";
}



void LDE::logInstructionAndAddressCtx(_In_ const LPBYTE& lpReferenceAddress, _In_ const BYTE& state, const BYTE& cbInstructionIndex) {
	using namespace std;
	LPBYTE lpReferenceForPrint = lpReferenceAddress;
	cout << format("#{:2d} @{:P} ", cbInstructionIndex, reinterpret_cast<LPVOID>(lpReferenceForPrint));
	BYTE cbInstructionLen = GetInstructionLenCtx(state);
	for (BYTE i = NULL; i < cbInstructionLen; i++) {
		cout << format("{:#04X} ", static_cast<BYTE>(*(lpReferenceForPrint + i)));
	}
	cout << "\n";
}

BOOLEAN LDE::find_n_fix_relocation(_Inout_ LPBYTE lpGateWayTrampoline, _In_ LPVOID lpTargetFunction, _In_ LDE_HOOKING_STATE& state) {
	if (!lpTargetFunction) {
		state.ecStatus = no_input;
		return FALSE;
	}
	BYTE *lpRipRelativeAddress		      = static_cast<LPBYTE>(state.lpFuncAddr),
	      cb_count_of_passed_instructions = NULL,
	      uc_size_passed				  = NULL;
	for (BYTE i = NULL; i < state.cb_count_of_rip_indexes; i++) {
		for (; cb_count_of_passed_instructions < state.rip_relative_indexes[i]; cb_count_of_passed_instructions++) {
			BYTE uc_instruction_size = GetInstructionLenCtx(state.contexts_arr[cb_count_of_passed_instructions]);
			uc_size_passed			+= uc_instruction_size;
			lpRipRelativeAddress	+= uc_instruction_size;
		}
		BYTE   cbInstructionLength = GetInstructionLenCtx(state.contexts_arr[cb_count_of_passed_instructions]),
		       cbOpCodeLength	   = get_index_opcode_len(state.rip_relative_indexes[i], state),
			   cbPrefixLength	   = get_index_prefix_count(cb_count_of_passed_instructions, state),
			  *lpOldTargetAddress  = lpRipRelativeAddress + cbInstructionLength + *reinterpret_cast<LPDWORD>(lpRipRelativeAddress + cbPrefixLength + cbOpCodeLength);
		hkUINT hkiNewDisposition   = lpOldTargetAddress   - (lpGateWayTrampoline + uc_size_passed + cbInstructionLength); 
		int	   iNewDisposition	   = static_cast<int>(hkiNewDisposition);
		memcpy(lpGateWayTrampoline + uc_size_passed + cbOpCodeLength + cbPrefixLength, &iNewDisposition, sizeof(iNewDisposition));
	}
	return TRUE;
}

template<typename STATE>
BOOLEAN LDE::is_curr_ctx_bREX_w(_In_ const STATE& state) {
	return (state.curr_instruction_ctx & REX_MASK) >> 6;
}

template<typename STATE>
BOOLEAN LDE::is_RIP_relative(_In_ const STATE& state) {
	return (state.curr_instruction_ctx & RIP_RELATIVE_MASK) >> 7;
}

BYTE LDE::GetInstructionLenCtx(_In_ const BYTE& ucCurrentInstruction_ctx) {
	return static_cast<BYTE>(ucCurrentInstruction_ctx & 0x3C) >> 2;
}

BYTE LDE::get_curr_opcode_len(const _In_ BYTE& ucCurrentInstruction_ctx) {
	return (ucCurrentInstruction_ctx & 0x03) + 1;
}

template<typename STATE>
BYTE LDE::get_index_opcode_len(_In_ const BYTE cbIndex, _In_ const STATE& state) {
	return (state.contexts_arr[cbIndex] & 0x03) + 1;
}

template<typename STATE>
BYTE LDE::get_index_ctx_inst_len(_In_ const BYTE cbIndex, _In_ const STATE& state) {
	return (state.contexts_arr[cbIndex] & 0x3C) >> 2;
}

void LDE::set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx) {
	ucInstruction_ctx |= REX_MASK;
}

void LDE::SetCurrentContextRipRel(_Inout_ BYTE& ucCurrentInstructionCtx) {
	ucCurrentInstructionCtx |= RIP_RELATIVE_MASK;
}

template<typename STATE>
BYTE LDE::get_index_prefix_count(const BYTE ucIndex, STATE& state) {
	if (ucIndex < state.cb_count_of_instructions) { return state.prefix_count_arr[ucIndex] & 0x0F; }
	state.ecStatus = wrong_input;
	return NULL;
}

template<typename STATE>
BYTE LDE::get_current_prefix_count(STATE& state) {
	return state.prefix_count_arr[state.cb_count_of_instructions] & 0x0F;
}

template<typename STATE>
void LDE::set_curr_inst_len(_In_ BYTE cbInstructionLength, _Inout_ STATE& state) {using namespace std;
	if (cbInstructionLength > MAX_INSTRUCTION_SIZE) {
		cout << format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0x0F!\n[i] Received instruction length: {:#X}\n", static_cast<int>(cbInstructionLength));
		return;
	}
	state.curr_instruction_ctx &= 0xC3;
	state.curr_instruction_ctx |= cbInstructionLength << 2;
}

template<typename STATE>
void LDE::set_curr_opcode_len(_In_ BYTE cbOpcodeLength, _Inout_ STATE& lde_state) {
	if (cbOpcodeLength < SIZE_OF_DWORD) {
		lde_state.curr_instruction_ctx &= 0xFC;
		lde_state.curr_instruction_ctx |= cbOpcodeLength - 1;
	} else {
		lde_state.ecStatus = opcode_overflow;
	}
}

template<typename STATE>
BYTE LDE::analyse_group3_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ STATE& state) {
	if (!*lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.ecStatus = success;
	BYTE ucReg				 = *(lpCandidate + SIZE_OF_BYTE) & REG_MASK,
		 ucRM				 = *(lpCandidate + SIZE_OF_BYTE) & RM_MASK,
		 ucMod				 = *(lpCandidate + SIZE_OF_BYTE) & MOD_MASK,
		 uc_added_opcode_len = NULL,
		 uc_added_imm_len	 = NULL;
	switch (*lpCandidate) {
		case 0xF6: {
			switch(ucMod) {
				case 0xC0: { if (0x10 > ucReg) { uc_added_imm_len++; } break; }
				case 0x80: {
					uc_added_imm_len ++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len += SIZE_OF_DWORD;
					}
					if (0x10 > ucReg) { uc_added_imm_len++; }
					break;
				}
				case 0x40: {
					uc_added_imm_len++;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
					}
					if (0x10 > ucReg) { uc_added_imm_len++; }
					break;
				}
				default: {
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + 2))) { uc_added_imm_len += SIZE_OF_DWORD; }
						break;
					}
					if (ucRM == 5) {
						SetCurrentContextRipRel(state.curr_instruction_ctx);
						uc_added_opcode_len++;
					}
					break;
				}
			}
			break;
		}
		case 0xF7: {
			switch (ucMod) {
				case 0xC0: { if (0x10 > ucReg) { uc_added_imm_len++; } break; }
				case 0x80: {
					uc_added_imm_len += 4;
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						if (analyse_sib_base(*(lpCandidate + SIZE_OF_WORD))) { uc_added_imm_len += SIZE_OF_DWORD; }
					}
					if (0x10 > ucReg) { uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state); }
					break;
				}
				case 0x40: {
					if (ucRM == 4) {
						increment_opcode_len(state);
						uc_added_opcode_len++;
						break;
					}
					if (0x10 > ucReg) { uc_added_imm_len += analyse_reg_size_0xF7(lpCandidate, state); }
					break;
				}
				default: { if (!ucReg) { uc_added_imm_len += SIZE_OF_DWORD; } break; }
			}
			break;
		}
		default: {
			state.ecStatus = wrong_input;
			return NULL;
		}
	}
	return uc_added_opcode_len + uc_added_imm_len;
}

template<typename STATE>
BYTE LDE::analyse_reg_size_0xF7(_In_ const LPBYTE lpCandidate, _In_ STATE& state) {
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.ecStatus = success;
	if (is_curr_instruction_shortened(get_current_prefix_count(state), lpCandidate)) {
		return SIZE_OF_WORD;
	}
	return SIZE_OF_DWORD;
}

template<typename STATE>
BYTE LDE::analyse_special_group(_In_ LPBYTE lpCandidate, _Inout_ STATE& state) {
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	state.ecStatus = success;
	switch (*lpCandidate) {
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
		case 0x0B: { return NULL; }
		case 0x3A:
		case 0xBA: {
			increment_opcode_len(state);
			return SIZE_OF_WORD + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
		case 0x38: {
			increment_opcode_len(state);
			return SIZE_OF_BYTE + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
		default: {
			if ((*lpCandidate & 0xF0) == 0x80) { return SIZE_OF_DWORD; }
			if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) { increment_opcode_len(state); }
			return SIZE_OF_BYTE + analyse_mod_rm(lpCandidate + SIZE_OF_BYTE, state);
		}
	}
}

template<typename STATE>
BYTE LDE::analyse_mod_rm(_In_ LPBYTE lpCandidate, _Inout_ STATE& state) {
	BYTE cbRM				 = *lpCandidate & RM_MASK,
		 cbReg				 = *lpCandidate & REG_MASK,
	     cbMod				 = *lpCandidate & MOD_MASK,
		 cb_added_opcode_len = NULL;
	state.ecStatus = success;
	if (!lpCandidate) {
		state.ecStatus = no_input;
		return NULL;
	}
	switch (cbMod) {
		case 0xC0: {
			break;
		}
		case 0x80: {
			cb_added_opcode_len += SIZE_OF_DWORD;
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < SIZE_OF_DWORD) {
					increment_opcode_len(state);
				}
				break;
			}
			if (cbReg < 0x10) {
				cb_added_opcode_len++;
			}
			break;
		}
		case 0x40: {
			cb_added_opcode_len++;
			if (cbRM == 4) {
				increment_opcode_len(state);
				cb_added_opcode_len++;
			}
			break;
		}
		default: {
			if (cbRM == 4) {
				cb_added_opcode_len++;
				if (get_curr_opcode_len(state.curr_instruction_ctx) < 4) {
					increment_opcode_len(state);
				}
				if (analyse_sib_base(*(lpCandidate + SIZE_OF_BYTE))) {
					cb_added_opcode_len += SIZE_OF_DWORD;
				}
				break;
			}
			if (cbRM == 5) {
				SetCurrentContextRipRel(state.curr_instruction_ctx);
				cb_added_opcode_len += SIZE_OF_DWORD;
				break;
			}
			break;
		}
	}
	return cb_added_opcode_len;
}

template<typename STATE>
void LDE::increment_inst_len(_Inout_ STATE& state) {
	if ((state.curr_instruction_ctx & 0x3C) < 0x3C) {
		BYTE cb_new_inst_len = static_cast<BYTE>((GetInstructionLenCtx(state.curr_instruction_ctx) + 1) << 2);
		state.curr_instruction_ctx &= 0xC3;
		state.curr_instruction_ctx |= cb_new_inst_len;
	}
	else {
		state.ecStatus = instruction_overflow;
	}
}

template<typename STATE>
void LDE::increment_opcode_len(STATE&state) {
	if ((state.curr_instruction_ctx & 0x03) < 3) {
		BYTE cb_new_opcode_len = (state.curr_instruction_ctx & 0x03) + 1;
		state.curr_instruction_ctx &= 0xFC;
		state.curr_instruction_ctx |= cb_new_opcode_len;
	} else {
		state.ecStatus = opcode_overflow;
	}
	return;
}

BOOLEAN LDE::analyse_sib_base(_In_ BYTE cbCandidate) {
	return (cbCandidate & 0x07) == 5;
}


WORD LDE::analyse_opcode_type(_In_ const LPBYTE& lpCandidate_addr, _Inout_ BYTE& ucInstructionContext_ref) {
	switch (*lpCandidate_addr)  {
		case 0xC2: { return ret | _far; }
		case 0xC3: { return  ret; }
		case 0xE8: {
			SetCurrentContextRipRel(ucInstructionContext_ref);
			return call;
		}
		case 0xE9: {
			SetCurrentContextRipRel(ucInstructionContext_ref);
			return jump;
		}
		case 0xEB: {
			SetCurrentContextRipRel(ucInstructionContext_ref);
			return jump | _short;
		}
		case 0x0F: {
			switch (*(lpCandidate_addr + 1)) {
				case 0x05: { return sys_call; }
				case 0x07: { return sys_ret; }
				case 0x34: { return sys_enter; }
				case 0x35: { return sys_exit; }
				default: {
					if ((*(lpCandidate_addr + 1) & 0xF0) == 0x80) {
						SetCurrentContextRipRel(ucInstructionContext_ref);
						return conditional | jump;
					}
					break;
				}
			}
			break;
		}
		case 0xFF: {
			switch ((*(lpCandidate_addr + 1) & REG_MASK) >> 3) {
				case 0: { return indirect_inc; }
				case 1: { return indirect_dec; }
				case 2: { return indirect_call; }
				case 3: { return indirect_far_call; }
				case 4: { return indirect_jump; }
				case 5: { return indirect_far_jump; }
				case 6: { return indirect_push; }
				default: { return unknown; }
			}
		}
		default: {
			if ((*lpCandidate_addr & 0xF0) == 0x70 || (*lpCandidate_addr & 0xFC) == 0xE0) {

				return conditional | _short | jump;
			}
			return unknown;
		}
	}
	return unknown;
}

BOOLEAN LDE::is_curr_instruction_shortened(const BYTE cbPrefixCount, LPBYTE lpReferenceAddress) {
	for (BYTE i = NULL; i < cbPrefixCount; i++) {
		if (*(lpReferenceAddress - i) == 0x66) {
			return TRUE;
		}
	}
	return FALSE;
}


void LDE::reset_hooking_contexts(_Inout_ LDE_HOOKING_STATE& state) {
	for (BYTE i = NULL; i < state.cb_count_of_instructions; i++) {
		state.contexts_arr[i]	  = NULL;
		state.prefix_count_arr[i] = NULL;
	}
	for (BYTE i = NULL; i < state.cb_count_of_rip_indexes; i++) { state.rip_relative_indexes[i] = NULL; }
	state.cb_count_of_rip_indexes  = NULL;
	state.curr_instruction_ctx	   = NULL;
	state.cb_count_of_instructions = NULL;

}


IS_NEW_BRANCH LDE::check_for_new_branch(LDE_STATE& state, const LPBYTE& lpReference) {
	if (!lpReference) {
		return algorithm_failed;
	}
	IS_NEW_BRANCH bState;
	switch (analyse_opcode_type(lpReference, state.curr_instruction_ctx)) {
		case conditional | _near  | jump: 
		case conditional | _short | jump: {
			bState = yes_reached_conditional_branch;
			break;
		}
		case indirect_far_jump:
		case indirect_jump:
		case jump:
		case _short | jump: {
			state.ecStatus = reached_end_of_branch;
			bState = yes_reached_non_conditional_branch;
			break;
		}
		case indirect_far_call:
		case indirect_call: 
		case call: {
			bState = yes_is_call;
			break;
		}
		case ret :
		case ret | _far: {
			bState = no_reached_ret;
			break;
		}
		default: {
			bState = no;
			break;
		}
	}
	return bState;
}

BOOLEAN LDE::traceIntoIAT(LDE_HOOKING_STATE& state) {
	switch (analyse_opcode_type(static_cast<BYTE *>(state.lpFuncAddr), state.curr_instruction_ctx)) {
		case indirect_far_jump:
		case indirect_jump: {
			BYTE cb_instruction_len = GetInstructionLenCtx(state.curr_instruction_ctx),
				* lpRef = static_cast<BYTE*>(state.lpFuncAddr),
				cb_opcode_len = get_curr_opcode_len(state.curr_instruction_ctx),
				cb_prefix_count = get_current_prefix_count(state);
			LPVOID lpDisposition = static_cast<BYTE*>(state.lpFuncAddr) + cb_opcode_len + cb_prefix_count;
			DWORD iDisposition = cb_instruction_len;
			iDisposition += *static_cast<PDWORD>(lpDisposition);
			lpRef += iDisposition;
			state.lpFuncAddr = *reinterpret_cast<LPVOID *>(lpRef);
			return TRUE;
		}
		case jump: {
			state.lpFuncAddr = static_cast<BYTE*>(state.lpFuncAddr) + GetInstructionLenCtx(state.curr_instruction_ctx) + *reinterpret_cast<int*>(static_cast<BYTE*>(state.lpFuncAddr) + get_curr_opcode_len(state.curr_instruction_ctx) + get_current_prefix_count(state));
			state.rip_relative_indexes[NULL] = NULL;
			state.cb_count_of_instructions	 = NULL;
			state.cb_count_of_rip_indexes	 = NULL;
			return TRUE;
		}
		default:
			FALSE;
	}
	return FALSE;

}