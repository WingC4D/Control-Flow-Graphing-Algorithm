#include "Lde.h"

BYTE Lde::mapInstructionLength(LPVOID analysis_address, BYTE& InstructionContext, LdeErrorCodes& status, BYTE& prefix_count) { //Main instruction decoding dispatcher
	if (!analysis_address) {
		status = no_input;
		return 0;
	}
	if (*static_cast<LPBYTE>(analysis_address) == 0xCC) {
#ifdef DEBUG
		std::println("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...", reinterpret_cast<DWORD64>(analysis_address));
#endif
		return 0;
	}
	status = success;
	BYTE* lpReferenceBuffer = static_cast<LPBYTE>(analysis_address);

	incrementInstructionLen(InstructionContext, status);
	switch (results[*lpReferenceBuffer]) {
	case none: {
		if (*lpReferenceBuffer == 0xC3 || *lpReferenceBuffer == 0xC2) {
			status = reached_end_of_function;
		}
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext), InstructionContext);
		break;
	}
	case has_mod_rm: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | prefix: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_special_group(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | special: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_group3_mod_rm(lpReferenceBuffer, InstructionContext, status, prefix_count), InstructionContext);
		break;
	}
	case has_mod_rm | imm_one_byte: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + SIZE_OF_BYTE + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_two_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + SIZE_OF_WORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_four_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + SIZE_OF_DWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_eight_bytes: {
		incrementOpcodeLenCtx(InstructionContext, status);
		setCurrentInstructionLength(prefix_count + SIZE_OF_QWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(lpReferenceBuffer + 1, InstructionContext, status), InstructionContext);
		break;
	}
	case has_mod_rm | imm_eight_bytes | imm_four_bytes: {
		std::cout << std::format("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})\n", reinterpret_cast<void*>(lpReferenceBuffer));
		break;
	}
	case imm_one_byte: {
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_BYTE, InstructionContext);
		break;
	}
	case imm_two_bytes: {
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_WORD, InstructionContext);
		break;
	}
	case imm_four_bytes: {
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_DWORD, InstructionContext);
		break;
	}
	case imm_eight_bytes: {
		setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_QWORD, InstructionContext);
		break;
	}
	case imm_four_bytes | imm_eight_bytes: {
		if (*lpReferenceBuffer == 0xE8 || *lpReferenceBuffer == 0xE9) {
			setContextRipRel(InstructionContext);
			if (!isCurrentInstructionShortened(prefix_count, lpReferenceBuffer)) {
				setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_DWORD, InstructionContext);
			}
			else {
				setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_WORD, InstructionContext);
			}
		}
		else if (isRexCtx(InstructionContext)) {
			if (*(lpReferenceBuffer - (getOpcodeLenCtx(InstructionContext) - SIZE_OF_BYTE)) & 0x48) {
				setCurrentInstructionLength(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_QWORD, InstructionContext);
				break;
			}
		}
		setCurrentInstructionLength(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_DWORD, InstructionContext);
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
		return mapInstructionLength(lpReferenceBuffer + 1, InstructionContext, status, prefix_count);
	}
	default: {
		status = wrong_input;
		std::println ("[?] WTH Is Going On?");
		return 0;
	}
	}
	return getInstructionLengthCtx(InstructionContext);
}

BYTE Lde::analyse_special_group(LPBYTE candidate_address, BYTE& InstructionContext, LdeErrorCodes& status) {
	if (!candidate_address) {
		status = no_input;
		return 0;
	}
	status = success;
	switch (*candidate_address) {
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
		case 0x0B: {
			return 0;
		}
		case 0x3A:
		case 0xBA: {
			incrementOpcodeLenCtx(InstructionContext, status);
			return SIZE_OF_WORD + analyse_mod_rm(candidate_address + SIZE_OF_BYTE, InstructionContext, status);
		}
		case 0x38: {
			incrementOpcodeLenCtx(InstructionContext, status);
			break;
		}
		default: {
			if ((*candidate_address & 0xF0) == 0x80) 
				return SIZE_OF_DWORD;
			if (getOpcodeLenCtx(InstructionContext) < 4) 
				incrementOpcodeLenCtx(InstructionContext, status);
			break;
		}
	}
	return SIZE_OF_BYTE + analyse_mod_rm(candidate_address + SIZE_OF_BYTE, InstructionContext, status);
}



LPBYTE Lde::resolveJump(_In_ LPBYTE to_resolve_address) {
	LdeJumpResolutionState State(to_resolve_address);
	if (!mapInstructionLength(State.lpFuncAddr, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount])) {
		return nullptr;
	}
	State.contextsArray[0]	   = State.currInstructionContext;
	BYTE   instruction_length  = getInstructionLengthCtx(State.currInstructionContext),
		   opcode_length	   = getOpcodeLenCtx(State.currInstructionContext),
		   disposition_size	   = instruction_length - State.getCurrentPrefixCount() - opcode_length;
	LPVOID disposition_address = to_resolve_address + instruction_length - disposition_size,
		   result;
	switch (analyseOpcodeType(to_resolve_address, State.currInstructionContext)) {
		case _short | jump:
		case _near  | jump:
		case call:
		case jump:
		case conditional | jump | _short: {
			switch (disposition_size) {
				case SIZE_OF_BYTE: {
					result = to_resolve_address + *static_cast<signed char*>(disposition_address) + instruction_length;
					break;
				}
				case SIZE_OF_DWORD: {
					result = to_resolve_address + *static_cast<int*>(disposition_address) + instruction_length;
					break;
				}
				default: {
					result = nullptr;
					break;
				}
			}
			break;
		}
		case indirect_call:
		case indirect_far_jump:
		case indirect_jump:
		case indirect_far_call: {
			switch (disposition_size) {
				case SIZE_OF_BYTE: {
					result = *reinterpret_cast<LPVOID *>(to_resolve_address + *static_cast<signed char*>(disposition_address) + instruction_length);
					break;
				}
				case SIZE_OF_DWORD: {
					result = *reinterpret_cast<LPVOID *>(to_resolve_address + *static_cast<int*>(disposition_address) + instruction_length);
					break;
				}
				default: {
					result = nullptr;
					break;
				}
			}
			break;
		}
		default: {
			result = nullptr;
			break;
		}
	}
	return static_cast<BYTE*>(result);
}

BYTE Lde::getValidInstructionsSizeHook(_Inout_ LPVOID&target_address, _Out_ LdeHookingState& State) {
	if (!target_address) {
		State.status = no_input;
		return 0;
	}
	State.functionAddress	  = target_address;
	BYTE *reference_address	  = static_cast<LPBYTE>(target_address),
		  accumulated_length  = mapInstructionLength(reference_address, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
	if (!accumulated_length) {
		State.status = wrong_input;
		return 0;
	}
	if (traceIntoIAT(State)) {
		resetHookingContexts(State);
		reference_address  = static_cast<LPBYTE>(State.functionAddress);
	    target_address	   = reference_address;
		accumulated_length = 0;
		if (!State.functionAddress) {
			return 0;
		}
	} else {
		prepareForNextStep(State);
		if (isRipRelativeCtx(State.currInstructionContext)) {
			State.ripRelativeIndexesArray[State.ripIndexesCount] = State.instructionCount;
			State.ripIndexesCount++;
		}
		reference_address += accumulated_length;
	}
	while (accumulated_length < RELATIVE_TRAMPOLINE_SIZE && State.status == success) {
		BYTE instruction_length = mapInstructionLength(reference_address, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
		if (!instruction_length) {
			State.functionAddress = analyseRedirectingInstruction(accumulated_length, State);
			resetHookingContexts(State);
			if (!State.functionAddress) {
				return 0;
			}
			reference_address = static_cast<LPBYTE>(State.functionAddress);
			target_address = reference_address;
			accumulated_length = 0;
			continue;
		}
#ifdef DEBUG
		log_1(reference_address, State);
#endif
		prepareForNextStep(State);
		if (*reference_address == opcodes::RETURN) {
			State.status = reached_end_of_function;
			break;
		}
		if (isRipRelativeCtx(State.currInstructionContext)) {
			State.ripRelativeIndexesArray[State.ripIndexesCount] = State.instructionCount;
			State.ripIndexesCount++;
		}
		accumulated_length += instruction_length;
		reference_address			+= instruction_length;
	}
#ifdef DEBUG
	log_1(reference_address, State);	
	log_2(cbInstructionCounter);
#endif
	if (State.status != success && State.status != reached_end_of_function) {
		return 0;
	}
	return accumulated_length;
}

LPBYTE Lde::analyseRedirectingInstruction(_In_ DWORD accumulated_length, _Inout_ LdeHookingState& State) {
	if (!State.instructionCount) {
		State.status = wrong_input;
		return nullptr;
	}
	BYTE   last_valid_index	  = State.instructionCount - 1,
		   instruction_length = getIndexInstructionLength(last_valid_index, State),
		   opcode_length	  = get_index_opcode_len(last_valid_index, State),
		   prefix_count		  = State.prefixCountArray[last_valid_index],
		  *reference_address  = static_cast<BYTE*>(State.functionAddress) + accumulated_length - instruction_length;
	LPVOID disposition_ptr	  = reference_address + opcode_length + prefix_count;
	switch (analyseOpcodeType(reference_address, State.currInstructionContext)) {
		case ret:
		case ret | _short :
		case ret | _near  :
		case ret | _far   :
		case ret | _near  | _far   :
		case ret | _short | _near  :
		case ret | _far   | _short :
		case ret | _near  | _short | _far: {
			State.status = reached_end_of_function;
			return reference_address;
		}
		case jump:
		case call: {
			INT32 i32RVA;
			isCurrentInstructionShortened(State.getCurrentPrefixCount(), reference_address) ?
				i32RVA = *static_cast<PINT16>(disposition_ptr):
				i32RVA = *static_cast<PINT32>(disposition_ptr);
			return reference_address + instruction_length + i32RVA;
		}
		case indirect_call:
		case indirect_far_call:
		case indirect_jump:
		case indirect_far_jump: {
			switch (instruction_length - opcode_length) {
				case SIZE_OF_BYTE: {
					signed char cbRVA = static_cast<signed char>(instruction_length) + *static_cast<signed char*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + cbRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + cbRVA);
				}
				case SIZE_OF_WORD: {
					short wRVA = instruction_length + *static_cast<short*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + wRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + wRVA);
				}
				case SIZE_OF_DWORD: {
					long dwRVA = instruction_length + *static_cast<long*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + dwRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + dwRVA);
				}
				case SIZE_OF_QWORD: {
					long long ullRVA = instruction_length + *static_cast<long long*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + ullRVA));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + ullRVA);
				}
				default: {
					State.status = wrong_input;
					return nullptr;
				}
			}
		}
		default: {
			State.status = wrong_input;
			return nullptr;
		}
	}
}


void Lde::log_1(_In_ const LPBYTE reference_address, _In_ const LdeHookingState& State) { using namespace std;
	BYTE accumulated_length	= reference_address - State.functionAddress,
		 instruction_length	= getInstructionLengthCtx(State.currInstructionContext),
		 opcode_length		= getOpcodeLenCtx(State.currInstructionContext),
		 prefix_count		= State.getCurrentPrefixCount(),
		 i;
	cout <<format(
		"[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}\n[i]",
		instruction_length,
		accumulated_length,
		*reference_address);
	
	if (prefix_count) {
		cout << " Found Prefix Bytes: ";
		for (i = 0; i < prefix_count; i++) {
			cout << format("{:#4X} ", *(reference_address + i));
		}
		cout << " | ";
	}
	if (opcode_length) {
		cout << "Found Opcode Bytes: ";
		for (i = prefix_count; i < prefix_count + opcode_length; i++) {
			cout << format("{:#X} ", *(reference_address + i));
		}
	}
	if (getInstructionLengthCtx(State.currInstructionContext) > opcode_length + prefix_count) {
		cout << " | Found Operands Bytes: ";
		for (i = prefix_count + opcode_length; i < instruction_length; i++) {
			cout << format("{:#04X} ", *(reference_address + i));
		}
	}
	cout << "\n\n";
}

template<typename STATE>
void Lde::log_2(BYTE instruction_count, _In_ STATE& State) {
	std::cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < instruction_count; i++) {
		std::cout << format("{:#4X}, ", State.contextsArray[i]);
	}
	std::cout << "\n";
}

void Lde::logInstructionAndAddress(_In_ LPBYTE reference_address, _In_ BYTE InstructionContext) {
	BYTE	instruction_length  = getInstructionLengthCtx(InstructionContext);
	LPVOID	lpReferenceForPrint = reference_address;
	std::cout << std::format("#{:2d} @{:P} ", InstructionContext, lpReferenceForPrint);
	for (BYTE i = 0; i < instruction_length; i++) {
		std::cout << std::format("{:#04X} ", *(reference_address + i));
	}
	std::cout << "\n";
}

void Lde::logInstructionAndAddressCtx(_In_ LPBYTE reference_address, _In_ BYTE CandidateContext, BYTE instruction_index) {
	std::cout << std::format("#{:3d} @{:P} ", instruction_index, reinterpret_cast<LPVOID>(reference_address));
	BYTE cbInstructionLen = getInstructionLengthCtx(CandidateContext);
	for (BYTE i = 0; i < cbInstructionLen; i++) {
		std::cout << std::format("{:#04X} ", *(reference_address + i));
	}
	std::cout << "\n";
}

BOOLEAN Lde::findAndFixRelocations(_Inout_ LPBYTE gateway_trampoline_ptr, _In_ LPVOID target_function_ptr, _In_ LdeHookingState& State) {
	if (!target_function_ptr) {
		State.status = no_input;
		return false;
	}
	BYTE *rip_relative_address		= static_cast<LPBYTE>(State.functionAddress),
	      passed_instructions_count = 0,
	      accumulated_length		= 0;
	for (BYTE i = 0; BYTE RipRelativeIndex: State.ripRelativeIndexesArray) {
		if (i >= State.ripIndexesCount) {
			break;
		}
		for (; passed_instructions_count < RipRelativeIndex; passed_instructions_count++) {
			BYTE instruction_length = getInstructionLengthCtx(State.contextsArray[passed_instructions_count]);
			accumulated_length	   += instruction_length;
			rip_relative_address   += instruction_length;
		}
		BYTE   instruction_length  = getInstructionLengthCtx(State.contextsArray[passed_instructions_count]),
			   opcode_length	     = get_index_opcode_len(passed_instructions_count, State),
			   prefix_count	     = State.prefixCountArray[passed_instructions_count],
			  *old_target_address  = rip_relative_address + instruction_length + *reinterpret_cast<LPDWORD>(rip_relative_address + prefix_count + opcode_length);
		hkUINT hkiNewDisposition = old_target_address   - (gateway_trampoline_ptr + accumulated_length + instruction_length);
		if (hkiNewDisposition < TWO_GIGABYTES) {
			int	iNewDisposition = static_cast<int>(hkiNewDisposition);
			memcpy(gateway_trampoline_ptr + accumulated_length + opcode_length + prefix_count, &iNewDisposition, sizeof(iNewDisposition));
		} else {
			return false;
		}
		i++;
	}
	return true;
}

BOOLEAN Lde::isRexCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & REX_MASK) >> 6;
}

BOOLEAN Lde::isRipRelativeCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & RIP_RELATIVE_MASK) >> 7;
}

BYTE Lde::getInstructionLengthCtx(_In_ const BYTE CandidateContext) {
	return static_cast<BYTE>(CandidateContext & 0x3C) >> 2;
}

BYTE Lde::getOpcodeLenCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & 0x03) + 1;
}

BYTE Lde::get_index_opcode_len(_In_ const BYTE index, _In_ const LdeHookingState& State) {
	return (State.contextsArray[index] & 0x03) + 1;
}

BYTE Lde::getIndexInstructionLength(_In_ const BYTE  index, _In_ const LdeHookingState& State) {
	return (State.contextsArray[index] & 0x3C) >> 2;
}

void Lde::set_curr_ctx_bRex_w(_Inout_ BYTE& ucInstruction_ctx) {
	ucInstruction_ctx |= REX_MASK;
}

void Lde::setContextRipRel(_Inout_ BYTE& CandidateContext) {
	CandidateContext |= RIP_RELATIVE_MASK;
}

void Lde::incrementInstructionLen(_Inout_ BYTE& CandidateContext, _Inout_ LdeErrorCodes& Status) {
	if ((CandidateContext & 0x3C) < 0x3C) {
		BYTE new_instruction_length = static_cast<BYTE>((getInstructionLengthCtx(CandidateContext) + 1) << 2);
		CandidateContext		   &= 0xC3;
		CandidateContext		   |= new_instruction_length;
	} else {
		Status = instruction_overflow;
	}
}

void Lde::incrementOpcodeLenCtx(BYTE& CandidateContext, LdeErrorCodes& Status) {
	if ((CandidateContext & 0x03) < 3) {
		BYTE cb_new_opcode_len = (CandidateContext & 0x03) + 1;
		CandidateContext &= 0xFC;
		CandidateContext |= cb_new_opcode_len;
	} else {
		Status = opcode_overflow;
	}
}

void Lde::setCurrentInstructionLength(_In_ BYTE instruction_length, _Inout_ BYTE& CandidateContext) {
	if (instruction_length > MAX_INSTRUCTION_SIZE) {
		std::println("[!] Error @ Lde::setCurrentInstructionLength, Value is greater than 0x0F!\n[i] Received instruction length: {:#X}", static_cast<int>(instruction_length));
		return;
	}
	CandidateContext &= 0xC3;
	CandidateContext |= instruction_length << 2;
}

BOOLEAN Lde::analyseSibBase(_In_ const BYTE candidate) {
	return (candidate & 0x07) == 5;
}



WORD Lde::analyseOpcodeType(_In_ const LPBYTE candidate_addr, _Inout_ BYTE& InstructionContext) {
	switch (*candidate_addr)  {
		case 0xC2: { return ret | _far; }
		case 0xC3: { return ret; }
		case 0xE8: {
			setContextRipRel(InstructionContext);
			return call;
		}
		case 0xE9: {
			setContextRipRel(InstructionContext);
			return jump;
		}
		case 0xEB: {
			setContextRipRel(InstructionContext);
			return jump | _short;
		}
		case 0x0F: {
			switch (*(candidate_addr + 1)) {
				case 0x05: { return sys_call;  }
				case 0x07: { return sys_ret;   }
				case 0x34: { return sys_enter; }
				case 0x35: { return sys_exit;  }
				default:   {
					if ((*(candidate_addr + 1) & 0xF0) == 0x80) {
						setContextRipRel(InstructionContext);
						return conditional | jump;
					}
					break;
				}
			}
			break;
		}
		case 0xFF: {
			switch ((*(candidate_addr + 1) & REG_MASK) >> 3) {
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
			if ((*candidate_addr & 0xF0) == 0x70 || (*candidate_addr & 0xFC) == 0xE0) {
				return conditional | _short | jump;
			}
			return unknown;
		}
	}
	return unknown;
}

BOOLEAN Lde::isCurrentInstructionShortened(const BYTE prefix_count, LPBYTE reference_address) {
	for (BYTE i = 0; i < prefix_count; i++) {
		if (*(reference_address - i) == 0x66) {
			return true;
		}
	}
	return false;
}

void Lde::resetHookingContexts(_Inout_ LdeHookingState& State) {
	for (BYTE i = 0; i < State.instructionCount; i++) {
		State.contextsArray[i]	  = 0;
		State.prefixCountArray[i] = 0;
	}
	for (BYTE i = 0; i < State.ripIndexesCount; i++) {
		State.ripRelativeIndexesArray[i] = 0;
	}
	State.ripIndexesCount		 = 0;
	State.currInstructionContext = 0;
	State.instructionCount		 = 0;
}


IsNewBranch Lde::checkForNewBlock(LdeState& state, LPBYTE lpReference) {
	if (!lpReference) {
		return algorithm_failed;
	}
	IsNewBranch result;
	switch (analyseOpcodeType(lpReference, state.currInstructionContext)) {
		case conditional | _near  | jump: 
		case conditional | _short | jump: {
			result = yes_reached_conditional_branch;
			break;
		}
		case indirect_far_jump:
		case indirect_jump:
		case jump:
		case _short | jump: {
			state.status = reached_end_of_branch;
			result = yes_reached_non_conditional_branch;
			break;
		}
		case indirect_far_call:
		case indirect_call: 
		case call: {
			result = yes_is_call;
			break;
		}
		case ret :
		case ret | _far: {
			result = no_reached_ret;
			break;
		}
		default: {
			result = no;
			break;
		}
	}
	return result;
}

BOOLEAN Lde::traceIntoIAT(LdeHookingState& state) {
	switch (analyseOpcodeType(static_cast<BYTE *>(state.functionAddress), state.currInstructionContext)) {
		case indirect_far_jump:
		case indirect_jump: {
			BYTE  instruction_length =  getInstructionLengthCtx(state.currInstructionContext),
				  opcode_length		 =  getOpcodeLenCtx(state.currInstructionContext),
				  prefix_count		 =  state.getCurrentPrefixCount();
			int   disposition		 = *reinterpret_cast<int*>(static_cast<BYTE*>(state.functionAddress) + opcode_length + prefix_count) + instruction_length;
			BYTE* reference_address  =  static_cast<BYTE*>(state.functionAddress) + disposition;
			state.functionAddress	 = *reinterpret_cast<LPVOID *>(reference_address);
			return TRUE;
		}
		case jump: {
			state.functionAddress			 = static_cast<BYTE*>(state.functionAddress) + getInstructionLengthCtx(state.currInstructionContext);
			state.ripRelativeIndexesArray[0] = 0;
			state.instructionCount			 = 0;
			state.ripIndexesCount			 = 0;
			return TRUE;
		}
		default:
			FALSE;
	}
	return FALSE;

}