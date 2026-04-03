#include "LDE.h"

BYTE LDE::mapInstructionLen(LPVOID lpCodeBuffer, BYTE& InstructionContext, lde_error_codes& status, BYTE& prefix_count) { //Main instruction decoding dispatcher
	if (!lpCodeBuffer) {
		status = no_input;
		return 0;
	}
	if (*static_cast<LPBYTE>(lpCodeBuffer) == 0xCC) {
#ifdef DEBUG
		std::println("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...", reinterpret_cast<DWORD64>(lpCodeBuffer));
#endif
		return 0;
	}
	status = success;
	BYTE* lpReferenceBuffer = static_cast<LPBYTE>(lpCodeBuffer);

	incrementInstructionLen(InstructionContext, status);
	switch (results[*lpReferenceBuffer]) {
	case none: {
		if (*lpReferenceBuffer == 0xC3 || *lpReferenceBuffer == 0xC2) {
			status = reached_end_of_function;
		}
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext), InstructionContext);
		break;
	}
	case has_mod_rm: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | prefix: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_special_group(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | special: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_group3_mod_rm(lpReferenceBuffer, InstructionContext, status, prefix_count), InstructionContext);
		break;
	}
	case has_mod_rm | imm_one_byte: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + SIZE_OF_BYTE + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_two_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + SIZE_OF_WORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_four_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + SIZE_OF_DWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_eight_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		set_curr_inst_len(prefix_count + SIZE_OF_QWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_eight_bytes | imm_four_bytes: {
		std::cout << std::format("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})\n", reinterpret_cast<void*>(lpReferenceBuffer));
		break;
	}
	case imm_one_byte: {
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_BYTE, InstructionContext);
		break;
	}
	case imm_two_bytes: {
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_WORD, InstructionContext);
		break;
	}
	case imm_four_bytes: {
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_DWORD, InstructionContext);
		break;
	}
	case imm_eight_bytes: {
		set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_QWORD, InstructionContext);
		break;
	}
	case imm_four_bytes | imm_eight_bytes: {
		if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9) {
			SetCurrentContextRipRel(InstructionContext);
			if (!is_curr_instruction_shortened(prefix_count, lpReferenceBuffer)) {
				set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_DWORD, InstructionContext);
			}
			else {
				set_curr_inst_len(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_WORD, InstructionContext);
			}
		}
		else if (isRexCtx(InstructionContext)) {
			if (*(lpReferenceBuffer - (getOpcodeLenCtx(InstructionContext) - SIZE_OF_BYTE)) & 0x48) {
				set_curr_inst_len(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_QWORD, InstructionContext);
				break;
			}
		}
		set_curr_inst_len(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_DWORD, InstructionContext);
		break;
	}
	case prefix: {
		prefix_count++;
		if (prefix_count > 0x0E) {
			status = prefix_overflow;
			return 0;
		}
		if ((results[*lpReferenceBuffer] & 0xF0) == 0x48) {
			set_curr_ctx_bRex_w(InstructionContext);
		}
		return mapInstructionLen(lpReferenceBuffer + 1, InstructionContext, status, prefix_count);
	}
	default: {
		status = wrong_input;
		std::println ("[?] WTH Is Going On?");
		return 0;
	}
	}
	return GetInstructionLenCtx(InstructionContext);
}


LPBYTE LDE::ResolveJump(_In_ LPBYTE lpSartAddress) {
	LDE_JUMP_RESOLUTION_STATE state(lpSartAddress);

	if (!mapInstructionLen(state.lpFuncAddr, state.curr_instruction_ctx, state.ecStatus, state.prefixCountArray[state.instructionCount])) {
		return nullptr;
	}
	state.contextsArray[0] = state.curr_instruction_ctx;
	BYTE   ucInstructionLength	= GetInstructionLenCtx(state.curr_instruction_ctx),
		   ucOpcodeLength		= getOpcodeLenCtx(state.curr_instruction_ctx),
		   ucDispositionSize	= ucInstructionLength - state.getCurrentPrefixCount() - ucOpcodeLength;
	LPVOID lpResult,
		   lpDispositionAddress = lpSartAddress + ucInstructionLength - ucDispositionSize;
	switch (analyse_opcode_type(lpSartAddress, state.curr_instruction_ctx)) {
		case _short | jump:
		case _near  | jump:
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

BYTE LDE::get_first_valid_instructions_size_hook(_Inout_ LPVOID&lpCodeBuffer, _Out_ LDE_HOOKING_STATE& state) {
	if (!lpCodeBuffer) {
		state.ecStatus = no_input;
		return 0;
	}
	state.lpFuncAddr		  = lpCodeBuffer;
	BYTE *lpReference		  = static_cast<LPBYTE>(lpCodeBuffer),
		  cbAccumulatedLength = mapInstructionLen(lpReference, state.curr_instruction_ctx, state.ecStatus, state.prefixCountArray[state.instructionCount]);
	if (!cbAccumulatedLength) {
		state.ecStatus = wrong_input;
		return 0;
	}
	if (traceIntoIAT(state)) {
		reset_hooking_contexts(state);
		lpReference			= static_cast<LPBYTE>(state.lpFuncAddr);
	   lpCodeBuffer			= lpReference;
		cbAccumulatedLength = 0;
		if (!state.lpFuncAddr) {
			return 0;
		}
	} else {
		prepareForNextStep(state);
		if (isRipRelativeCtx(state.curr_instruction_ctx)) {
			state.rip_relative_indexes[state.cb_count_of_rip_indexes] = state.instructionCount;
			state.cb_count_of_rip_indexes++;
		}
		lpReference += cbAccumulatedLength;
	}
	while (cbAccumulatedLength < RELATIVE_TRAMPOLINE_SIZE && state.ecStatus == success) {
		BYTE cbCurrentInstructionLength = mapInstructionLen(lpReference, state.curr_instruction_ctx, state.ecStatus, state.prefixCountArray[state.instructionCount]);
		if (!cbCurrentInstructionLength) {
			state.lpFuncAddr = analyse_redirecting_instruction(cbAccumulatedLength, state);
			reset_hooking_contexts(state);
			if (!state.lpFuncAddr) {
				return 0;
			}
			lpReference = static_cast<LPBYTE>(state.lpFuncAddr);
			lpCodeBuffer = lpReference;
			cbAccumulatedLength = 0;
			continue;
		}
#ifdef DEBUG
		log_1(lpReference, state);
#endif
		prepareForNextStep(state);
		if (*lpReference == opcodes::RETURN) {
			state.ecStatus = reached_end_of_function;
			break;
		}
		if (isRipRelativeCtx(state.curr_instruction_ctx)) {
			state.rip_relative_indexes[state.cb_count_of_rip_indexes] = state.instructionCount;
			state.cb_count_of_rip_indexes++;
		}
		cbAccumulatedLength += cbCurrentInstructionLength;
		lpReference			+= cbCurrentInstructionLength;
	}
#ifdef DEBUG
	log_1(lpReference, state);	
	log_2(cbInstructionCounter);
#endif
	if (state.ecStatus != success && state.ecStatus != reached_end_of_function) {
		return 0;
	}
	return cbAccumulatedLength;
}

LPBYTE LDE::analyse_redirecting_instruction(_In_ DWORD cbAccumulatedLength, _Inout_ LDE_HOOKING_STATE& state) {
	if (!state.instructionCount) {
		state.ecStatus = wrong_input;
		return nullptr;
	}
	BYTE	  ucLastValidIndex	  = state.instructionCount - 1,
			  cbInstructionLength = get_index_ctx_inst_len(ucLastValidIndex, state),
			  cbOpcodeLength	  = get_index_opcode_len(ucLastValidIndex, state),
		      cbPrefixCount		  = state.prefixCountArray[ucLastValidIndex],
			 *lpReferenceAddress  = static_cast<LPBYTE>(state.lpFuncAddr) + cbAccumulatedLength - cbInstructionLength;
	LPVOID    lpDisposition		  = lpReferenceAddress + cbOpcodeLength + cbPrefixCount;
	switch (analyse_opcode_type(lpReferenceAddress, state.curr_instruction_ctx)) {
		case ret:
		case ret | _short :
		case ret | _near  :
		case ret | _far   :
		case ret | _near  | _far   :
		case ret | _short | _near  :
		case ret | _far   | _short :
		case ret | _near  | _short | _far: {
			state.ecStatus = reached_end_of_function;
			return lpReferenceAddress;
		}
		case jump:
		case call: {
			INT32 i32RVA;
			is_curr_instruction_shortened(state.getCurrentPrefixCount(), lpReferenceAddress) ?
			  i32RVA = *static_cast<PINT16>(lpDisposition)
			: i32RVA = *static_cast<PINT32>(lpDisposition);
			return lpReferenceAddress + cbInstructionLength + i32RVA;
		}
		case indirect_call:
		case indirect_far_call:
		case indirect_jump:
		case indirect_far_jump: {
			switch (cbInstructionLength - cbOpcodeLength) {
				case SIZE_OF_BYTE: {
					BYTE cbRVA = cbInstructionLength;
					cbRVA	  += *static_cast<LPBYTE>(lpDisposition);
#ifdef DEBUG
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + cbRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + cbRVA);
				}
				case SIZE_OF_WORD: {
					WORD wRVA = cbInstructionLength;
					wRVA	 += *static_cast<PWORD>(lpDisposition);
#ifdef DEBUG
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + wRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + wRVA);
				}
				case SIZE_OF_DWORD: {
					DWORD dwRVA = cbInstructionLength;
					dwRVA	   += *static_cast<PDWORD>(lpDisposition);
#ifdef DEBUG
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + dwRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(lpReferenceAddress + dwRVA);
				}
				case SIZE_OF_QWORD: {
					ULONGLONG ullRVA = cbInstructionLength;
					ullRVA		    += *static_cast<PULONGLONG>(lpDisposition);
#ifdef DEBUG
					std::cout << std::format("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(lpReferenceAddress), *reinterpret_cast<PULONGLONG>(lpReferenceAddress + ullRVA));
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
		for (i = 0; i < cbCurrentPrefixCount; i++) {
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
void LDE::log_2(BYTE cbInstructionCounter, _In_ STATE& lde_state) { using namespace std;
	cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < cbInstructionCounter; i++) {
		cout << format("{:#4X}, ", retinterpret_cast<BYTE>(lde_state.contextsArray[i]));
	}
	cout << "\n";
}

template<typename STATE>
void LDE::logInstructionAndAddress(_In_ LPBYTE lpReferenceAddress, _In_ const STATE& state) {
	BYTE	cbInstructionLen    = GetInstructionLenCtx(state.curr_instruction_ctx);
	LPVOID	lpReferenceForPrint = lpReferenceAddress;
	std::cout << std::format("#{:2d} @{:P} ",state.instructionCount, lpReferenceForPrint);
	for (BYTE i = 0; i < cbInstructionLen; i++) {
		std::cout << std::format("{:#04X} ", *(lpReferenceAddress + i));
	}
	std::cout << "\n";
}

void LDE::logInstructionAndAddressCtx(_In_ LPBYTE lpReferenceAddress, _In_ BYTE CandidateContext, BYTE cbInstructionIndex) {
	std::cout << std::format("#{:3d} @{:P} ", cbInstructionIndex, reinterpret_cast<LPVOID>(lpReferenceAddress));
	BYTE cbInstructionLen = GetInstructionLenCtx(CandidateContext);
	for (BYTE i = 0; i < cbInstructionLen; i++) {
		std::cout << std::format("{:#04X} ", *(lpReferenceAddress + i));
	}
	std::cout << "\n";
}

BOOLEAN LDE::find_n_fix_relocation(_Inout_ LPBYTE lpGateWayTrampoline, _In_ LPVOID lpTargetFunction, _In_ LDE_HOOKING_STATE& state) {
	if (!lpTargetFunction) {
		state.ecStatus = no_input;
		return false;
	}
	BYTE *lpRipRelativeAddress		= static_cast<LPBYTE>(state.lpFuncAddr),
	      passed_instructions_count = 0,
	      accumulated_length		= 0;
	for (BYTE i = 0; BYTE RipRelativeIndex: state.rip_relative_indexes) {
		if (i >= state.cb_count_of_rip_indexes) {
			break;
		}
		for (; passed_instructions_count < RipRelativeIndex; passed_instructions_count++) {
			BYTE uc_instruction_size = GetInstructionLenCtx(state.contextsArray[passed_instructions_count]);
			accumulated_length		+= uc_instruction_size;
			lpRipRelativeAddress	+= uc_instruction_size;
		}
		BYTE   cbInstructionLength = GetInstructionLenCtx(state.contextsArray[passed_instructions_count]),
		       cbOpCodeLength	   = get_index_opcode_len(passed_instructions_count, state),
			   cbPrefixLength	   = state.prefixCountArray[passed_instructions_count],
			  *lpOldTargetAddress  = lpRipRelativeAddress + cbInstructionLength  + *reinterpret_cast<LPDWORD>(lpRipRelativeAddress + cbPrefixLength + cbOpCodeLength);
		hkUINT hkiNewDisposition   = lpOldTargetAddress   - (lpGateWayTrampoline + accumulated_length + cbInstructionLength);
		if (hkiNewDisposition < TWO_GIGABYTES) {
			int	   iNewDisposition = static_cast<int>(hkiNewDisposition);
			memcpy(lpGateWayTrampoline + accumulated_length + cbOpCodeLength + cbPrefixLength, &iNewDisposition, sizeof(iNewDisposition));
		} else {
			return false;
		}
		i++;
	}
	return true;
}

BOOLEAN LDE::isRexCtx(_In_ BYTE CandidateContext) {
	return (CandidateContext & REX_MASK) >> 6;
}

BOOLEAN LDE::isRipRelativeCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & RIP_RELATIVE_MASK) >> 7;
}

BYTE LDE::GetInstructionLenCtx(_In_ BYTE ucCurrentInstruction_ctx) {
	return static_cast<BYTE>(ucCurrentInstruction_ctx & 0x3C) >> 2;
}

BYTE LDE::getOpcodeLenCtx(_In_ BYTE ucCurrentInstruction_ctx) {
	return (ucCurrentInstruction_ctx & 0x03) + 1;
}

BYTE LDE::get_index_opcode_len(_In_ const BYTE cbIndex, _In_ const LDE_HOOKING_STATE& state) {
	return (state.contextsArray[cbIndex] & 0x03) + 1;
}

BYTE LDE::get_index_ctx_inst_len(_In_ const BYTE cbIndex, _In_ const LDE_HOOKING_STATE& state) {
	return (state.contextsArray[cbIndex] & 0x3C) >> 2;
}

void LDE::set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx) {
	ucInstruction_ctx |= REX_MASK;
}

void LDE::SetCurrentContextRipRel(_Inout_ BYTE& ucCurrentInstructionCtx) {
	ucCurrentInstructionCtx |= RIP_RELATIVE_MASK;
}

void LDE::incrementInstructionLen(_Inout_ BYTE& CandidateContext, _Inout_ lde_error_codes& Status) {
	if ((CandidateContext & 0x3C) < 0x3C) {
		BYTE cb_new_inst_len = static_cast<BYTE>((GetInstructionLenCtx(CandidateContext) + 1) << 2);
		CandidateContext &= 0xC3;
		CandidateContext |= cb_new_inst_len;
	}
	else {
		Status = instruction_overflow;
	}
}

void LDE::incrementOpcodeLenCtx(BYTE& CandidateContext, lde_error_codes& StatusCode) {
	if ((CandidateContext & 0x03) < 3) {
		BYTE cb_new_opcode_len = (CandidateContext & 0x03) + 1;
		CandidateContext &= 0xFC;
		CandidateContext |= cb_new_opcode_len;
	}
	else {
		StatusCode = opcode_overflow;
	}
}

void LDE::set_curr_inst_len(_In_ BYTE cbInstructionLength, _Inout_ BYTE& CandidateContext) {
	if (cbInstructionLength > MAX_INSTRUCTION_SIZE) {
		std::cout << std::format("[!] Error @ LDE::set_curr_inst_len, Value is greater than 0x0F!\n[i] Received instruction length: {:#X}\n", static_cast<int>(cbInstructionLength));
		return;
	}
	CandidateContext &= 0xC3;
	CandidateContext |= cbInstructionLength << 2;
}

BOOLEAN LDE::analyse_sib_base(_In_ BYTE cbCandidate) {
	return (cbCandidate & 0x07) == 5;
}


WORD LDE::analyse_opcode_type(_In_ const LPBYTE lpCandidate_addr, _Inout_ BYTE& InstructionContext_ref) {
	switch (*lpCandidate_addr)  {
		case 0xC2: { return ret | _far; }
		case 0xC3: { return ret; }
		case 0xE8: {
			SetCurrentContextRipRel(InstructionContext_ref);
			return call;
		}
		case 0xE9: {
			SetCurrentContextRipRel(InstructionContext_ref);
			return jump;
		}
		case 0xEB: {
			SetCurrentContextRipRel(InstructionContext_ref);
			return jump | _short;
		}
		case 0x0F: {
			switch (*(lpCandidate_addr + 1)) {
				case 0x05: { return sys_call;  }
				case 0x07: { return sys_ret;   }
				case 0x34: { return sys_enter; }
				case 0x35: { return sys_exit;  }
				default:   {
					if ((*(lpCandidate_addr + 1) & 0xF0) == 0x80) {
						SetCurrentContextRipRel(InstructionContext_ref);
						return conditional | jump;
					}
					break;
				}
			}
			break;
		}
		case 0xFF: {
			switch ((*(lpCandidate_addr + 1) & REG_MASK) >> 3) {
				case 0:  { return indirect_inc;		 }
				case 1:  { return indirect_dec;		 }
				case 2:  { return indirect_call;	 }
				case 3:  { return indirect_far_call; }
				case 4:  { return indirect_jump;	 }
				case 5:  { return indirect_far_jump; }
				case 6:  { return indirect_push;	 }
				default: { return unknown; }
			}
			break;
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
	for (BYTE i = 0; i < cbPrefixCount; i++) {
		if (*(lpReferenceAddress - i) == 0x66) {
			return TRUE;
		}
	}
	return FALSE;
}

void LDE::reset_hooking_contexts(_Inout_ LDE_HOOKING_STATE& state) {
	for (BYTE i = 0; i < state.instructionCount; i++) {
		state.contextsArray[i]	  = 0;
		state.prefixCountArray[i] = 0;
	}
	for (BYTE i = 0; i < state.cb_count_of_rip_indexes; i++) {
		state.rip_relative_indexes[i] = 0;
	}
	state.cb_count_of_rip_indexes  = 0;
	state.curr_instruction_ctx	   = 0;
	state.instructionCount		   = 0;
}


IS_NEW_BRANCH LDE::checkForNewBlock(LDE_STATE& state, LPBYTE lpReference) {
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
			BYTE  cb_instruction_len =  GetInstructionLenCtx(state.curr_instruction_ctx),
				  cb_opcode_len		 =  getOpcodeLenCtx(state.curr_instruction_ctx),
				  cb_prefix_count	 =  state.getCurrentPrefixCount();
			int   iDisposition		 = *reinterpret_cast<int*>(static_cast<BYTE*>(state.lpFuncAddr) + cb_opcode_len + cb_prefix_count) + cb_instruction_len;
			BYTE* lpRef				 =  static_cast<BYTE*>(state.lpFuncAddr) + iDisposition;
			state.lpFuncAddr		 = *reinterpret_cast<LPVOID *>(lpRef);
			return TRUE;
		}
		case jump: {
			state.lpFuncAddr = static_cast<BYTE*>(state.lpFuncAddr) + GetInstructionLenCtx(state.curr_instruction_ctx);
			state.rip_relative_indexes[0] = 0;
			state.instructionCount		  = 0;
			state.cb_count_of_rip_indexes = 0;
			return TRUE;
		}
		default:
			FALSE;
	}
	return FALSE;

}