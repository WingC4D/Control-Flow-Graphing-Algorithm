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
	BYTE* reference_address = static_cast<LPBYTE>(analysis_address);
	incrementInstructionLen(InstructionContext, status);
	switch (results[*reference_address]) {
		case none: 
			if (*reference_address == opcodes::RETURN || *reference_address == 0xC2) 
				status = reached_end_of_function;
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext), InstructionContext);
			break;
		
		case has_mod_rm: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | prefix: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_special_group(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | special: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + analyse_group3_mod_rm(reference_address, InstructionContext, status, prefix_count), InstructionContext);
			break;
		
		case has_mod_rm | imm_one_byte: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + SIZE_OF_BYTE + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | imm_two_bytes: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + SIZE_OF_WORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | imm_four_bytes: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + SIZE_OF_DWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | imm_eight_bytes: 
			incrementOpcodeLenCtx(InstructionContext, status);
			setCurrentInstructionLength(prefix_count + SIZE_OF_QWORD + getOpcodeLenCtx(InstructionContext) + analyse_mod_rm(reference_address, InstructionContext, status), InstructionContext);
			break;
		
		case has_mod_rm | imm_eight_bytes | imm_four_bytes: 
			std::println("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})", reinterpret_cast<void*>(reference_address));
			break;
		
		case imm_one_byte: 
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_BYTE, InstructionContext);
			break;
		
		case imm_two_bytes: 
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_WORD, InstructionContext);
			break;
		
		case imm_four_bytes: 
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_DWORD, InstructionContext);
			break;
		
		case imm_eight_bytes: 
			setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + SIZE_OF_QWORD, InstructionContext);
			break;
		
		case imm_four_bytes | imm_eight_bytes: 
			if (*reference_address == opcodes::CALL || *reference_address == opcodes::JUMP) {
				setContextRipRel(InstructionContext);
				setCurrentInstructionLength(prefix_count + getOpcodeLenCtx(InstructionContext) + isCurrentInstructionShortened(prefix_count, reference_address) ? SIZE_OF_WORD : SIZE_OF_DWORD, InstructionContext);
			} else if (isRexCtx(InstructionContext)) {
				if (*(reference_address - (getOpcodeLenCtx(InstructionContext) - SIZE_OF_BYTE)) & 0x48) {
					setCurrentInstructionLength(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_QWORD, InstructionContext);
					break;
				}
			}
			setCurrentInstructionLength(getOpcodeLenCtx(InstructionContext) + prefix_count + SIZE_OF_DWORD, InstructionContext);
			break;
		
		case prefix: 
			prefix_count++;
			if (prefix_count >= MAX_PREFIX_COUNT) {
				status = prefix_overflow;
				return 0;
			}
			if ((results[*reference_address] & 0xF8) == 0x48) 
				set_curr_ctx_bRex_w(InstructionContext);
			return mapInstructionLength(reference_address + 1, InstructionContext, status, prefix_count);
		
		default: 
			status = wrong_input;
			std::println ("[?] WTH Is Going On?");
			return 0;
		
	}
	status = success;
	return getInstructionLengthCtx(InstructionContext);
}
BYTE Lde::analyse_mod_rm(LPBYTE preceding_byte_ptr, BYTE& InstructionContext, LdeErrorCodes& status) {
	preceding_byte_ptr++;
	BYTE rm_bits			 = *preceding_byte_ptr & RM_MASK,
		 reg_bits			 = *preceding_byte_ptr & REG_MASK,
	     mod_bits			 = *preceding_byte_ptr & MOD_MASK,
		 added_opcode_length = 0;
	status = success;
	if (!preceding_byte_ptr) {
		status = no_input;
		return 0;
	}
	switch (mod_bits) {
		case 0xC0: 
			break;
		case 0x80: 
			added_opcode_length += SIZE_OF_DWORD;
			if (rm_bits == 4) {
				added_opcode_length++;
				if (getOpcodeLenCtx(InstructionContext) < SIZE_OF_DWORD) 
					incrementOpcodeLenCtx(InstructionContext, status);
				break;
			}
			if (reg_bits < 0x10) 
				added_opcode_length++;
			break;
		
		case 0x40: 
			added_opcode_length++;
			if (rm_bits == 4) {
				incrementOpcodeLenCtx(InstructionContext, status);
				added_opcode_length++;
			}
			break;
		
		default: 
			if (rm_bits == 4) {
				added_opcode_length++;
				if (getOpcodeLenCtx(InstructionContext) < 4) 
					incrementOpcodeLenCtx(InstructionContext, status);
				if (analyseSibBase(*(preceding_byte_ptr + SIZE_OF_BYTE))) 
					added_opcode_length += SIZE_OF_DWORD;
				break;
			}
			if (rm_bits == 5) {
				setContextRipRel(InstructionContext);
				added_opcode_length += SIZE_OF_DWORD;
				break;
			}
			break;
		
	}
	return added_opcode_length;
}

BYTE Lde::analyse_special_group(LPBYTE candidate_address, BYTE& InstructionContext, LdeErrorCodes& status) {
	if (!candidate_address) {
		status = no_input;
		return 0;
	}
	candidate_address++;
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
		case 0x0B: 
			return 0;
		
		case 0x3A:
		case 0xBA: 
			incrementOpcodeLenCtx(InstructionContext, status);
			return SIZE_OF_WORD + analyse_mod_rm(candidate_address, InstructionContext, status);
		
		case 0x38: 
			incrementOpcodeLenCtx(InstructionContext, status);
			break;
		
		default: 
			if ((*candidate_address & 0xF0) == 0x80) 
				return SIZE_OF_DWORD;
			if (getOpcodeLenCtx(InstructionContext) < 4) 
				incrementOpcodeLenCtx(InstructionContext, status);
			break;
	}
	return 1 + analyse_mod_rm(candidate_address, InstructionContext, status);
}

BYTE Lde::analyse_group3_mod_rm(LPBYTE lpCandidate, BYTE& InstructionContext, LdeErrorCodes& status, BYTE prefix_count){
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
				case 0xC0: 
					if (0x10 > reg_bits)
						added_immediate_length++;
					break;
				
				case 0x80: 
					added_immediate_length ++;
					if (rm_bits == 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
						added_opcode_length += SIZE_OF_DWORD;
					}
					if (0x10 > reg_bits) 
						added_immediate_length++;
					break;
				
				case 0x40: 
					added_immediate_length++;
					if (rm_bits == 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
						added_opcode_length++;
					}
					if (0x10 > reg_bits) 
						added_immediate_length++;
					break;
				
				default: 
					if (rm_bits == 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
						added_opcode_length++;
						if (analyseSibBase(*(lpCandidate + 2))) 
							added_immediate_length += SIZE_OF_DWORD;
						break;
					}
					if (rm_bits == 5) {
						setContextRipRel(InstructionContext);
						added_opcode_length++;
					}
					break;
			}
			break;
		}
		case 0xF7: 
			switch (mod_bits) {
				case 0xC0: 
					if (0x10 > reg_bits) 
						added_immediate_length++;
					break;
				
				case 0x80: 
					added_immediate_length += SIZE_OF_DWORD;
					if (rm_bits == 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
						added_opcode_length++;
						if (analyseSibBase(*(lpCandidate + SIZE_OF_WORD)))
							added_immediate_length += SIZE_OF_DWORD;
					}
					if (0x10 > reg_bits)
						added_immediate_length += analyseRegSizeF7(lpCandidate, status, prefix_count);
					break;
				
				case 0x40: 
					if (rm_bits == 4) {
						incrementOpcodeLenCtx(InstructionContext, status);
						added_opcode_length++;
						break;
					}
					if (0x10 > reg_bits) 
						added_immediate_length += analyseRegSizeF7(lpCandidate, status, prefix_count);
					break;
				
				default: 
					if (!reg_bits) 
						added_immediate_length += SIZE_OF_DWORD;
					break;
			}
			break;

		default: 
			status = wrong_input;
			return 0;
	}
	return added_opcode_length + added_immediate_length;
}


LPBYTE Lde::resolveJump(_In_ LPBYTE to_resolve_address) {
	LdeJumpResolutionState State(to_resolve_address);
	if (!mapInstructionLength(State.toResolve, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]))
		return nullptr;
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
		case conditional | jump | _short: 
			switch (disposition_size) {
				case SIZE_OF_BYTE: {
					result = to_resolve_address + *static_cast<CHAR*>(disposition_address) + instruction_length;
					break;
				}
				case SIZE_OF_DWORD: {
					result = to_resolve_address + *static_cast<INT*>(disposition_address) + instruction_length;
					break;
				}
				default: 
					result = nullptr;
					break;
			}
			break;

		case indirect_call:
		case indirect_far_jump:
		case indirect_jump:
		case indirect_far_call: 
			switch (disposition_size) {
				case SIZE_OF_BYTE: 
					result = *reinterpret_cast<LPVOID*>(to_resolve_address + *static_cast<CHAR*>(disposition_address) + instruction_length);
					break;
				
				case SIZE_OF_DWORD: 
					result = *reinterpret_cast<LPVOID*>(to_resolve_address + *static_cast<INT*>(disposition_address) + instruction_length);
					break;
				
				default: 
					result = nullptr;
					break;
			}
			break;

		default: 
			result = nullptr;
			break;
	}
	return static_cast<BYTE*>(result);
}

BYTE Lde::getValidInstructionsSizeHook(_Inout_ LPVOID&target_address, _Out_ LdeHookingState& State) {
	if (!target_address) {
		State.status = no_input;
		return 0;
	}
	State.functionAddress	 = target_address;
	BYTE *reference_address	 = static_cast<LPBYTE>(target_address),
		  accumulated_length = mapInstructionLength(reference_address, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
	if (!accumulated_length) {
		State.status = wrong_input;
		return 0;
	}
	if (traceIntoIAT(State)) {
		if (!State.functionAddress)
			return 0;
		resetHookingContexts(State);
		reference_address  = static_cast<LPBYTE>(State.functionAddress);
	    target_address	   = reference_address;
		accumulated_length = 0;
	} else {
		State.prepareForNextStep();
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
			if (!State.functionAddress) 
				return 0;
			resetHookingContexts(State);
			reference_address  = static_cast<LPBYTE>(State.functionAddress);
			target_address	   = reference_address;
			accumulated_length = 0;
			continue;
		}
#ifdef DEBUG
		log_1(reference_address, State);
#endif
		State.prepareForNextStep();
		if (*reference_address == opcodes::RETURN) {
			State.status = reached_end_of_function;
			break;
		}
		if (isRipRelativeCtx(State.currInstructionContext)) {
			State.ripRelativeIndexesArray[State.ripIndexesCount] = State.instructionCount;
			State.ripIndexesCount++;
		}
		accumulated_length += instruction_length;
		reference_address  += instruction_length;
	}
#ifdef DEBUG
	log_1(reference_address, State);	
	log_2(cbInstructionCounter);
#endif
	return State.status != success && State.status != reached_end_of_function ? 0 : accumulated_length;
}

LPBYTE Lde::analyseRedirectingInstruction(const DWORD accumulated_length, _Inout_ LdeHookingState& State) {
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
		case ret | _near  | _short | _far: 
			State.status = reached_end_of_function;
			return reference_address;
		
		case jump:
		case call:
			return reference_address + instruction_length + (isCurrentInstructionShortened(State.getCurrentPrefixCount(), reference_address) ? *static_cast<PINT16>(disposition_ptr) : *static_cast<PINT32>(disposition_ptr));

		case indirect_call:
		case indirect_far_call:
		case indirect_jump:
		case indirect_far_jump: {
			switch (instruction_length - opcode_length) {
				case SIZE_OF_BYTE: {
					CHAR rva = static_cast<signed char>(instruction_length) + *static_cast<signed char*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + rva));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + rva);
				}
				case SIZE_OF_WORD: {
					SHORT rva = static_cast<SHORT>(instruction_length) + *static_cast<short*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + rva));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + rva);
				}
				case SIZE_OF_DWORD: {
					long rva = instruction_length + *static_cast<long*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + rva));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + rva);
				}
				case SIZE_OF_QWORD: {
					long long rva = instruction_length + *static_cast<long long*>(disposition_ptr);
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(reference_address + rva));
#endif
					return *reinterpret_cast<LPBYTE *>(reference_address + rva);
				}
				default: 
					State.status = wrong_input;
					return nullptr;
			}
		}
		default: 
			State.status = wrong_input;
			return nullptr;
	}
}


void Lde::log_1(_In_ const LPBYTE reference_address, _In_ LdeHookingState& State) {
	BYTE accumulated_length	= reference_address - State.functionAddress,
		 instruction_length	= getInstructionLengthCtx(State.currInstructionContext),
		 opcode_length		= getOpcodeLenCtx(State.currInstructionContext),
		 prefix_count		= State.getCurrentPrefixCount(),
		 i = 0;
	std::println("[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}", instruction_length, accumulated_length, *reference_address);
	std::cout << "[i]";
	if (prefix_count) {
		std::cout << " Found Prefix Bytes: ";
		for (; i < prefix_count; i++) 
			std::cout << std::format("{:#4X} ", *(reference_address + i));
		std::cout << " | ";
	}
	if (opcode_length) {
		std::cout << "Found Opcode Bytes: ";
		for (; i < prefix_count + opcode_length; i++)
			std::cout << std::format("{:#X} ", *(reference_address + i));
	}
	if (getInstructionLengthCtx(State.currInstructionContext) > opcode_length + prefix_count) {
		std::cout << " | Found Operands Bytes: ";
		for (; i < instruction_length; i++) 
			std::cout << std::format("{:#04X} ", *(reference_address + i));
	}
	std::cout << "\n\n";
}

template<typename STATE>
void Lde::log_2(BYTE instruction_count, _In_ STATE& State) {
	std::cout << "[i] Held contexts: ";
	for (BYTE i = 0; i < instruction_count; i++) 
		std::cout << format("{:#4X}, ", State.contextsArray[i]);
	std::cout << "\n";
}

void Lde::logInstructionAndAddress(const LPBYTE reference_address, const BYTE InstructionContext) {
	std::cout << std::format("#{:3d} @{:P} ", InstructionContext, reinterpret_cast<void*>(reference_address));
	for (BYTE i = 0, instruction_length = getInstructionLengthCtx(InstructionContext); i < instruction_length; i++)
		std::cout << std::format("{:#04X} ", *(reference_address + i));
	std::cout << "\n";
}

void Lde::logInstructionAndAddressCtx(const LPBYTE reference_address, const BYTE CandidateContext, const BYTE instruction_index) {
	std::cout << std::format("#{:3d} @{:P} ", instruction_index, reinterpret_cast<LPVOID>(reference_address));
	for (BYTE passed_bytes = 0, instruction_length = getInstructionLengthCtx(CandidateContext); passed_bytes < instruction_length; passed_bytes++)
		std::cout << std::format("{:#04X} ", *(reference_address + passed_bytes));
	std::cout << "\n";
}

BOOLEAN Lde::findAndFixRelocations(_Inout_ LPBYTE trampoline_gateway_address, _In_ LdeHookingState& State) {
	for (BYTE array_idx = 0, accumulated_length = 0, passed_instructions = 0, *rip_relative_address = static_cast<LPBYTE>(State.functionAddress);
		 BYTE rip_relative_idx: State.ripRelativeIndexesArray) {
		if (array_idx >= State.ripIndexesCount) 
			break;
		for (BYTE instruction_length; passed_instructions < rip_relative_idx; passed_instructions++) {
			instruction_length		= getInstructionLengthCtx(State.contextsArray[passed_instructions]);
			accumulated_length	   += instruction_length;
			rip_relative_address   += instruction_length;
			
		}
		BYTE   instruction_length		= getInstructionLengthCtx(State.contextsArray[passed_instructions]),
			   opcode_length			= get_index_opcode_len(passed_instructions, State),
			   prefix_count				= State.prefixCountArray[passed_instructions],
			  *old_target_address		= rip_relative_address + instruction_length + *reinterpret_cast<int*>(rip_relative_address + prefix_count + opcode_length);
		hkUINT new_disposition_unsigned = old_target_address - (trampoline_gateway_address + accumulated_length + instruction_length);
		if (new_disposition_unsigned < TWO_GIGABYTES) {
			int	new_disposition = static_cast<int>(new_disposition_unsigned);
			memcpy(trampoline_gateway_address + accumulated_length + opcode_length + prefix_count, &new_disposition, sizeof(new_disposition));
		} else 
			return false;
		array_idx++;
	}
	return true;
}

BOOLEAN Lde::isRexCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & REX_MASK) >> 6;
}

BOOLEAN Lde::isRipRelativeCtx(_In_ const BYTE CandidateContext) {
	return (CandidateContext & RIP_RELATIVE_MASK) >> 7;
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

void Lde::set_curr_ctx_bRex_w(_Inout_ BYTE& InstructionContext) {
	InstructionContext |= REX_MASK;
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
		BYTE new_opcode_length = (CandidateContext & 0x03) + 1;
		CandidateContext &= 0xFC;
		CandidateContext |= new_opcode_length;
	} else 
		Status = opcode_overflow;
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
		case 0xC2:
			return ret | _far;

		case opcodes::RETURN:
			return ret;

		case opcodes::CALL: 
			setContextRipRel(InstructionContext);
			return call;
		
		case opcodes::JUMP: 
			setContextRipRel(InstructionContext);
			return jump;
		
		case 0xEB: 
			setContextRipRel(InstructionContext);
			return jump | _short;
		
		case 0x0F: 
			switch (*(candidate_addr + 1)) {
				case 0x05:
					return sys_call;  

				case 0x07:
					return sys_ret;   

				case 0x34:
					return sys_enter; 

				case 0x35:
					return sys_exit;  

				default:   
					if ((*(candidate_addr + 1) & 0xF0) == 0x80) {
						setContextRipRel(InstructionContext);
						return conditional | jump;
					}
					return unknown;
			}

		case 0xFF: 
			switch ((*(candidate_addr + 1) & REG_MASK) >> 3) {
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
					return unknown; 
			}

		default: 
			return (*candidate_addr & 0xF0) == 0x70 || (*candidate_addr & 0xFC) == 0xE0 ? conditional | _short | jump : unknown;
	}
}

BOOLEAN Lde::isCurrentInstructionShortened(const BYTE prefix_count, const LPBYTE reference_address) {
	for (BYTE i = 0; i < prefix_count; i++) 
		if (*(reference_address - i) == 0x66) 
			return true;
	return false;
}

void Lde::resetHookingContexts(_Inout_ LdeHookingState& State) {
	for (BYTE i = 0; i < State.ripIndexesCount; i++)
		State.ripRelativeIndexesArray[i] = 0;
	for (BYTE i = 0; i < State.instructionCount; i++) {
		State.contextsArray[i]	  = 0;
		State.prefixCountArray[i] = 0;
	}
	State.ripIndexesCount		 = 0;
	State.currInstructionContext = 0;
	State.instructionCount		 = 0;
}

blk::TraceResults Lde::checkForNewBlock(BYTE& InstructionContext, const LPBYTE lpReference) {
	using namespace blk;
	if (!lpReference)
		return failed;
	switch (analyseOpcodeType(lpReference, InstructionContext)) {
		case conditional | _near | jump:
		case conditional | _short | jump:
			return reachedConditionalJump;

		case indirect_far_jump:
		case indirect_jump:
		case jump:
		case _short | jump:
			return reachedJump;

		case indirect_far_call:
		case indirect_call:
		case call:
			return reachedCall;

		case ret:
		case ret | _far:
			return reachedReturn;

		default:
			return noNewBlock;
	}
}

BOOLEAN Lde::traceIntoIAT(LdeHookingState& State) {
	switch (analyseOpcodeType(static_cast<BYTE *>(State.functionAddress), State.currInstructionContext)) {
		case indirect_far_jump:
		case indirect_jump: {
			BYTE  instruction_length =  getInstructionLengthCtx(State.currInstructionContext),
				  opcode_length		 =  getOpcodeLenCtx(State.currInstructionContext),
				  prefix_count		 =  State.getCurrentPrefixCount();
			int   disposition		 = *reinterpret_cast<int*>(static_cast<BYTE*>(State.functionAddress) + opcode_length + prefix_count) + instruction_length;
			State.functionAddress	 = *reinterpret_cast<LPVOID*>(static_cast<BYTE*>(State.functionAddress) + disposition);
			return true;
		}
		case jump: {
			State.functionAddress			 = static_cast<BYTE*>(State.functionAddress) + getInstructionLengthCtx(State.currInstructionContext) + *reinterpret_cast<LPINT>(static_cast<LPBYTE>(State.functionAddress) + 1);
			State.ripRelativeIndexesArray[0] = 0;
			State.instructionCount			 = 0;
			State.ripIndexesCount			 = 0;
			return true;
		}
		default:
			return false;
	}
}