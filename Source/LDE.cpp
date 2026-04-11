#include "Lde.h"
#include <iostream>
BYTE Lde::mapInstructionLength(const BYTE* analysis_address, inst::Context& InstructionContext, inst::Context::Status& status) { //Main instruction decoding dispatcher
    using enum inst::Context::Status;
    if (!analysis_address) {
		status = no_input;
		return 0;
	}
	BYTE instruction_length = InstructionContext.getPreDisposition();
	if (!InstructionContext.setLength(InstructionContext.getPreDisposition())){
		status = instruction_overflow;
		return 0;
	}
	if (*analysis_address == 0xCC) {
#ifdef DEBUG
		std::println("[!] Found Uninitialised memory @: {:#10X} Now Examining The Last instruction...", reinterpret_cast<DWORD64>(analysis_address));
#endif
		return 0;
	}
    BOOLEAN check = InstructionContext.getPrefixCount() == 0;

 	switch (results[*analysis_address]) {
		case none: 
			if (*analysis_address == opcodes::RETURN || *analysis_address == 0xC2)
				status = reached_end_of_function;
		break;
		
		case has_mod_rm:
			++instruction_length += analyseModRm(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | prefix: 
			++instruction_length += analyseSpecialGroup(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | special: 
			++instruction_length += analyseGroup3(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | imm_one_byte: 
			++instruction_length += SIZE_OF_BYTE  + analyseModRm(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | imm_two_bytes: 
			++instruction_length += SIZE_OF_WORD  + analyseModRm(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | imm_four_bytes: 
			++instruction_length += SIZE_OF_DWORD + analyseModRm(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | imm_eight_bytes: 
			++instruction_length += SIZE_OF_QWORD + analyseModRm(analysis_address, InstructionContext, status);
			break;
		
		case has_mod_rm | imm_eight_bytes | imm_four_bytes: 
			std::println("[x] You don't handle yet has_mod_rm | imm_eight_bytes | imm_four_bytes, (Found @{:p})", reinterpret_cast<const void*>(analysis_address));
			break;
		
		case imm_one_byte:
			if (!InstructionContext.increaseLength(SIZE_OF_BYTE)) {
				status = instruction_overflow;
				return 0;
			}
			instruction_length += SIZE_OF_BYTE;
			break;
		
		case imm_two_bytes:
			if (!InstructionContext.increaseLength(SIZE_OF_WORD)) {
				status = instruction_overflow;
				return 0;
			}
			instruction_length += SIZE_OF_WORD;
			break;
		
		case imm_four_bytes:
			if (!InstructionContext.increaseLength(SIZE_OF_DWORD)) {
				status = instruction_overflow;
				return 0;
			}
			instruction_length += SIZE_OF_DWORD;
			break;
		
		case imm_eight_bytes:
			if (!InstructionContext.increaseLength(SIZE_OF_QWORD)) {
				status = instruction_overflow;
				return 0;
			}
			instruction_length += SIZE_OF_QWORD;
			break;
		
		case imm_four_bytes | imm_eight_bytes: 
			if (*analysis_address == opcodes::CALL || *analysis_address == opcodes::JUMP)
				InstructionContext.setRipRelative();
			if (!InstructionContext.increaseLength(SIZE_OF_DWORD)) {
				status = instruction_overflow;
				return 0;
			}
			instruction_length += InstructionContext.isRexW() ? SIZE_OF_QWORD : SIZE_OF_DWORD;
			break;
		
		case prefix: 
			if (!InstructionContext.incrementPrefixCount()) {
				status = prefix_overflow;
				return 0;
			}
			if (!InstructionContext.incrementLength()) {
				status = instruction_overflow;
				return 0;
			}
			if ((*analysis_address & 0xF8) == 0x48)
				InstructionContext.setRexW();

			return mapInstructionLength(analysis_address + 1, InstructionContext, status);
		
		default: 
			status = wrong_input;
			std::println ("[?] WTH Is Going On?");
			return 0;
		
	}
    
    if (check) {
        inst::Context ctx{};
        auto result = ctx.map(analysis_address);

        if (result != success && result != reached_end_of_function)
            std::cout << "";

        if (ctx.getLength() != instruction_length)
		    InstructionContext.setLength(instruction_length);
    }
    InstructionContext.setLength(instruction_length);
	return status != success && status != reached_end_of_function ? 0 : InstructionContext.getLength();
}

BYTE Lde::analyseModRm(const BYTE* preceding_byte_ptr, inst::Context& InstructionContext, inst::Context::Status& status) {
    using enum inst::Context::Status;
    if (!preceding_byte_ptr) {
		status = no_input;
		return 0;
	}
	if (!InstructionContext.incrementOpcode()) {
		status = opcode_overflow;
		return 0;
	}
	if (!InstructionContext.incrementLength()) {
		status = instruction_overflow;
		return 0;
	}
	BYTE rm_bits	  = preceding_byte_ptr[1] & RM_MASK,
	     mod_bits	  = preceding_byte_ptr[1] & MOD_MASK,
		 added_length = 0;
	status = success;
	switch (mod_bits) {
		case 0xC0: 
			break;
		case 0x80:
			if (!InstructionContext.increaseLength(SIZE_OF_DWORD)) {
				status = instruction_overflow;
				return 0;
			}
			added_length += SIZE_OF_DWORD;
			if (rm_bits == 4) {
				if (!InstructionContext.incrementOpcode()) {
					status = opcode_overflow;
					return 0;
				}
				if (!InstructionContext.incrementLength()) {
					status = instruction_overflow;
					return 0;
				}
				added_length++;
			}
			break;
		
		case 0x40: 
			added_length++;
			if (!InstructionContext.incrementLength()) {
				status = instruction_overflow;
				return 0;
			}
			if (rm_bits == 4) {
				if (!InstructionContext.incrementLength()) {
					status = instruction_overflow;
					return 0;
				}
				added_length++;
			}
			break;
		
		default: 
			if (rm_bits == 4) {
				added_length++;
                if (!InstructionContext.incrementOpcode()) {
                    status = opcode_overflow;
                    return 0;
                }
				if (!InstructionContext.incrementLength()) {
					status = instruction_overflow;
					return 0;
				}
				if (analyseSibBase(preceding_byte_ptr[2])) {
					added_length += SIZE_OF_DWORD;
				}
				break;
			}
			if (rm_bits == 5) {
				InstructionContext.setRipRelative();
				added_length += SIZE_OF_DWORD;
				break;
			}
			break;
	}
	return added_length;
}

BYTE Lde::analyseSpecialGroup(const BYTE* candidate_address, inst::Context& InstructionContext, inst::Context::Status& status) {
    using enum inst::Context::Status;
    if (!candidate_address) {
		status = no_input;
		return 0;
	}
	if(!InstructionContext.incrementOpcode()) {
		status = opcode_overflow;
		return 0;
	}
	status = success;
	switch (candidate_address[1]) {
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
			return SIZE_OF_WORD + analyseModRm(1 + candidate_address, InstructionContext, status);
		
		case 0x38: 
			return SIZE_OF_BYTE + analyseModRm(1 + candidate_address, InstructionContext, status);
		
		default: 
			return (candidate_address[1] & 0xF0) == 0x80 ? SIZE_OF_DWORD : SIZE_OF_BYTE + analyseModRm(1 + candidate_address, InstructionContext, status);
	}
}

BYTE Lde::analyseGroup3(const BYTE* lpCandidate, inst::Context& InstructionContext, inst::Context::Status& status){
    using enum inst::Context::Status;
    if (!*lpCandidate) {
		status = no_input;
		return 0;
	}
	BYTE reg_bits				= lpCandidate[1] & REG_MASK,
		 rm_bits				= lpCandidate[1] & RM_MASK,
		 mod_bits				= lpCandidate[1] & MOD_MASK,
		 added_opcode_length	= 0,
		 added_immediate_length	= 0;
	switch (lpCandidate[0]) {
		case 0xF6: {
			switch(mod_bits) {
				case 0xC0: 
					if (0x10 > reg_bits)
						++added_immediate_length;
					break;
				
				case 0x80: 
					++added_immediate_length;
					if (rm_bits == 4) {
						if (!InstructionContext.incrementOpcode()) {
							status = opcode_overflow;
							return 0;
						}
						added_opcode_length += SIZE_OF_DWORD;
					}
					if (0x10 > reg_bits) 
						++added_immediate_length;
					break;
				
				case 0x40: 
					++added_immediate_length;
					if (rm_bits == 4) {
						if (!InstructionContext.incrementOpcode()) {
							status = opcode_overflow;
							return 0;
						}
						++added_opcode_length;
					}
					if (0x10 > reg_bits) 
						++added_immediate_length;
					break;
				
				default: 
					if (rm_bits == 4) {
						if (!InstructionContext.incrementOpcode()) {
							status = opcode_overflow;
							return 0;
						}
						++added_opcode_length;
						if (analyseSibBase(lpCandidate[2])) 
							added_immediate_length += SIZE_OF_DWORD;
						break;
					}
					if (rm_bits == 5) {
						InstructionContext.setRipRelative();
						++added_opcode_length;
					}
					break;
			}
			break;
		}
		case 0xF7: 
			switch (mod_bits) {
				case 0xC0: 
					if (0x10 > reg_bits) 
						++added_immediate_length;
					break;
				
				case 0x80: 
					added_immediate_length += SIZE_OF_DWORD;
					if (rm_bits == 4) {
						if (!InstructionContext.incrementOpcode()) {
							status = opcode_overflow;
							return 0;
						}
						added_opcode_length++;
						if (analyseSibBase(lpCandidate[2]))
							added_immediate_length += SIZE_OF_DWORD;
					}
					if (0x10 > reg_bits)
						added_immediate_length += analyseRegSizeF7(lpCandidate, status, InstructionContext.getPrefixCount());
					break;
				
				case 0x40: 
					if (rm_bits == 4) {
						if (!InstructionContext.incrementOpcode()) {
							status = opcode_overflow;
							return 0;
						}
						added_opcode_length++;
						break;
					}
					if (0x10 > reg_bits) 
						added_immediate_length += analyseRegSizeF7(lpCandidate, status, InstructionContext.getPrefixCount());
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
	status = success;
	return added_opcode_length + added_immediate_length;
}

LPBYTE Lde::resolveJump(const LPBYTE address_to_resolve) {
	LdeJumpResolutionState State(address_to_resolve);
	if (!mapInstructionLength(static_cast<BYTE*>(State.toResolve), State.currContext, State.status))
		return nullptr;

	*State.contextsArray	   = State.currContext;
	BYTE   disposition_size	   = State.currContext.getDisposition();
	LPVOID disposition_address = address_to_resolve + State.currContext.getPreDisposition(),
		   result			   = nullptr;
	switch (analyseOpcodeType(address_to_resolve, State.currContext)) {
		case _short | jump:
		case _near  | jump:
		case call:
		case jump:
		case conditional | jump | _short: 
		switch (disposition_size) {
			case SIZE_OF_BYTE:
					result = State.currContext.getLength() + address_to_resolve + *static_cast<signed char *>(disposition_address);
					break;
				
				case SIZE_OF_DWORD: 
					result = State.currContext.getLength() + address_to_resolve + *static_cast<int *>(disposition_address);
					break;
				
				default: 
					break;
			}
			break;

		case indirect_call:
		case indirect_far_jump:
		case indirect_jump:
		case indirect_far_call: 
			switch (disposition_size) {
				case SIZE_OF_BYTE: 
					result = *reinterpret_cast<LPVOID*>(State.currContext.getLength() + address_to_resolve + *static_cast<signed char*>(disposition_address));
					break;

				case SIZE_OF_DWORD:
					result = *reinterpret_cast<LPVOID*>(State.currContext.getLength() + address_to_resolve + *static_cast<int *>(disposition_address));
					break;
				
				default: 
					break;
			}

		default: 
			break;
	}
	return static_cast<BYTE*>(result);
}

BYTE Lde::getValidInstructionsSizeHook(_Inout_ const void*&target_address, _Out_ LdeHookingState& State) {
    using enum inst::Context::Status;
	if (!target_address) {
		State.status = no_input;
		return 0;
	}
	State.functionAddress	 = static_cast<const BYTE *>(target_address);
    const BYTE* reference_address = static_cast<const BYTE*>(target_address);
		  BYTE  accumulated_length = mapInstructionLength(reference_address, State.currContext, State.status);
	if (!accumulated_length) {
		State.status = wrong_input;
		return 0;
	}
	if (traceIntoIAT(State)) {
		if (!State.functionAddress)
			return 0;
		State.reset();
		reference_address  = State.functionAddress;
	    target_address	   = reference_address;
		accumulated_length = 0;
	} else {
		State.prepareForNextStep();
		if (State.currContext.isRexW()) {
			State.ripRelativeIndexesArray[State.rip_indexes_count] = State.instruction_count;
			State.rip_indexes_count++;
		}
		reference_address += accumulated_length;
	}
	while (accumulated_length < RELATIVE_TRAMPOLINE_SIZE && State.status == success) {
		BYTE instruction_length = mapInstructionLength(reference_address, State.currContext, State.status);
		if (!instruction_length) {
			State.functionAddress = analyseRedirectingInstruction(accumulated_length, State);
			if (!State.functionAddress) 
				return 0;
			State.reset();
			reference_address  = State.functionAddress;
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
		if (State.currContext.isRipRelative()) {
			State.ripRelativeIndexesArray[State.rip_indexes_count] = State.instruction_count;
			State.rip_indexes_count++;
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

const BYTE* Lde::analyseRedirectingInstruction(const DWORD accumulated_length, _Inout_ LdeHookingState& State) { using enum inst::Context::Status;
	if (!State.instruction_count) {
		State.status = wrong_input;
		return nullptr;
	}
    const BYTE  last_valid_index  = State.instruction_count - 1,
	          * reference_address = State.functionAddress + accumulated_length;
	const void* disposition_ptr   = reference_address + 
		State.contextsArray[last_valid_index].getOpcodeLength() + 
		State.contextsArray[last_valid_index].getPrefixCount();

	switch (analyseOpcodeType(reference_address, State.currContext)) {
		case ret:
		case ret | _short :
		case ret | _near  :
		case ret | _far   :
		case ret | _near  | _far   :
		case ret | _short | _near  :
		case ret | _far   | _short :
		case ret | _near  | _short | _far: 
			State.status = reached_end_of_function;
			return reference_address - State.contextsArray[last_valid_index].getLength();
		
		case jump:
		case call: {
			State.contextsArray[last_valid_index].setRipRelative();
			return reference_address + *static_cast<const int*>(disposition_ptr) + State.contextsArray[last_valid_index].getLength();
		}
		case indirect_call:
		case indirect_far_call: 
		case indirect_jump:
		case indirect_far_jump: {
			switch (State.contextsArray[last_valid_index].getLength() - State.contextsArray[last_valid_index].getPreDisposition()) {
				case SIZE_OF_BYTE: 
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG(&reference_address[instruction_length + *static_cast<long*>(disposition_ptr)]);
#endif
					return *reinterpret_cast<BYTE const * const *>(reference_address + *static_cast<const signed char*>(disposition_ptr) + State.contextsArray[last_valid_index].getLength());

				case SIZE_OF_WORD:
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG(&reference_address[instruction_length + *static_cast<long*>(disposition_ptr)]);
#endif
					return *reinterpret_cast<BYTE const * const *>(reference_address + *static_cast<const short*>(disposition_ptr) + State.contextsArray[last_valid_index].getLength());

				case SIZE_OF_DWORD:
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG(&reference_address[instruction_length + *static_cast<long*>(disposition_ptr)]);
#endif
					return *reinterpret_cast<BYTE const* const*>(reference_address + *static_cast<const long*>(disposition_ptr) + State.contextsArray[last_valid_index].getLength());

				case SIZE_OF_QWORD: 
#ifdef DEBUG
					std::println("[i] Moving RIP from: {:#12x} to: {:#12x}\n", reinterpret_cast<ULONGLONG>(reference_address), *reinterpret_cast<PULONGLONG>(&reference_address[instruction_length + *static_cast<long*>(disposition_ptr)]);
#endif
					return *reinterpret_cast<BYTE const* const*>(reference_address + *static_cast<const long long*>(disposition_ptr) + State.contextsArray[last_valid_index].getLength());
				
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


void Lde::log_1(const BYTE *reference_address, const LdeHookingState& State) {
	const BYTE accumulated_length   = static_cast<const BYTE>(reinterpret_cast<const long long>(reference_address) - reinterpret_cast<const long long>(State.functionAddress)),
		       instruction_length   = State.currContext.getLength(),
		       opcode_length        = State.currContext.getOpcodeLength(),
		       prefix_count	        = State.currContext.getPrefixCount();
	BYTE       bytes_passed         = 0;
	std::println("[i] Current Instruction Length:      {:#04X}\n[i] Accumulated Instructions Length: {:#06X}", instruction_length, accumulated_length, *reference_address);
	std::cout << "[i]";
	if (prefix_count) {
		std::cout << " Found Prefix Bytes: ";
		for (; bytes_passed < prefix_count; bytes_passed++) 
			std::cout << std::format("{:#4X} ", reference_address[bytes_passed]);
		std::cout << " | ";
	}
	if (opcode_length) {
		std::cout << "Found Opcode Bytes: ";
		for (; bytes_passed < prefix_count + opcode_length; bytes_passed++)
			std::cout << std::format("{:#X} ", reference_address[bytes_passed]);
	}
	if (State.currContext.getLength() > opcode_length + prefix_count) {
		std::cout << " | Found Operands Bytes: ";
		for (; bytes_passed < instruction_length; bytes_passed++) 
			std::cout << std::format("{:#04X} ", reference_address[bytes_passed]);
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

void Lde::logInstructionAndAddress(const LPBYTE reference_address, const inst::Context InstructionContext) {
	std::cout << std::format(" @{:P} ", reinterpret_cast<void*>(reference_address));
	for (BYTE i = 0, instruction_length = InstructionContext.getLength(); i < instruction_length; i++)
		std::cout << std::format("{:#04X} ", reference_address[i]);
	std::cout << "\n";
}

void Lde::logInstructionAndAddressCtx(const BYTE* reference_address, const inst::Context CandidateContext, const BYTE instruction_index) {
	std::cout << std::format("#{:3d} @{:P} ", instruction_index, reinterpret_cast<const void *>(reference_address));
	for (BYTE i = 0, instruction_length = CandidateContext.getLength(); i < instruction_length; i++)
		std::cout << std::format("{:#04X} ", reference_address[i]);
	std::cout << "\n";
}

BOOLEAN Lde::findAndFixRelocations(BYTE *trampoline_gateway_address, const LdeHookingState& State) {
	for (BYTE array_idx = 0, accumulated_length = 0, passed_instructions = 0;
		 BYTE rip_relative_idx: State.ripRelativeIndexesArray) {
		if (array_idx >= State.rip_indexes_count) 
			break;
		for (BYTE instruction_length; passed_instructions < rip_relative_idx; passed_instructions++) {
			instruction_length		= State.contextsArray[passed_instructions].getLength();
			accumulated_length	   += instruction_length;
			
		}
		BYTE   instruction_length		= State.contextsArray[passed_instructions].getLength(),
			   opcode_length			= State.contextsArray[passed_instructions].getOpcodeLength(),
			   prefix_count				= State.contextsArray[passed_instructions].getPrefixCount();
		BYTE *old_target_address		= const_cast<BYTE *>(State.functionAddress + accumulated_length + instruction_length + *reinterpret_cast<const int*>(State.functionAddress + accumulated_length + prefix_count + opcode_length));
		L_UINT new_disposition_unsigned = old_target_address - (trampoline_gateway_address + accumulated_length + instruction_length);
		if (new_disposition_unsigned >= TWO_GIGABYTES) 
			return false;
		int	new_disposition = static_cast<int>(new_disposition_unsigned);
		memcpy(trampoline_gateway_address + accumulated_length + opcode_length + prefix_count, &new_disposition, sizeof(new_disposition));	
		array_idx++;
	}
	return true;
}

BOOLEAN Lde::analyseSibBase(_In_ const BYTE candidate) {
	return (candidate & 0x07) == 5;
}

WORD Lde::analyseOpcodeType(const BYTE* candidate_addr, _Inout_ inst::Context& InstructionContext) {
	switch (*candidate_addr)  {
		case 0xC2:
			return ret | _far;

		case opcodes::RETURN:
			return ret;

		case opcodes::CALL: 
			InstructionContext.setRipRelative();
			return call;
		
		case opcodes::JUMP: 
			InstructionContext.setRipRelative();
			return jump;
		
		case 0xEB: 
			InstructionContext.setRipRelative();
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
					if ((candidate_addr[1] & 0xF0) == 0x80) {
						InstructionContext.setRipRelative();
						return conditional | jump;
					}
					return unknown;
			}

		case 0xFF: 
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
					return unknown; 
			}

		default: 
			return (*candidate_addr & 0xF0) == 0x70 || (*candidate_addr & 0xFC) == 0xE0 ? conditional | _short | jump : unknown;
	}
}
block::TraceResults Lde::checkForNewBlock(inst::Context& InstructionContext, const BYTE* lpReference) {
    using inst::opcodes::types;
    using enum block::TraceResults;
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
BOOLEAN Lde::isCurrentInstructionShortened(const BYTE prefix_count, const BYTE* reference_address) {
	for (BYTE i = 0; i < prefix_count; i++) 
		if (reference_address[-i] == 0x66) 
			return true;
	return false;
}


BOOLEAN Lde::traceIntoIAT(LdeHookingState& State) {
	switch (analyseOpcodeType(State.functionAddress, State.currContext)) {
		case indirect_far_jump:
		case indirect_jump: {
			State.functionAddress = State.functionAddress + *reinterpret_cast<const int*>(State.functionAddress + State.currContext.getOpcodeLength() + State.currContext.getPrefixCount()) + State.currContext.getLength();
			return true;
		}
		case jump: {
			State.functionAddress			 = State.functionAddress + State.currContext.getLength() + *reinterpret_cast<const int *>(State.functionAddress + 1);
			State.ripRelativeIndexesArray[0] = 0;
			State.instruction_count			 = 0;
			State.rip_indexes_count			 = 0;
			return true;
		}
		default:
			return false;
	}
}
void addResolvedCall(std::vector<const BYTE*>& NewFunctionVec, const BYTE* resolved_address) {
    for (const BYTE* stored_func_address : NewFunctionVec)
        if (stored_func_address == resolved_address)
            return;

    NewFunctionVec.emplace_back(resolved_address);
}
block::TraceResults LdeState::traceBlock(const BYTE* const block_root, std::vector<const BYTE*>& NewFunctionsVec) {using enum block::TraceResults;
    while (instruction_count < BLOCK_MAX_INSTRUCTIONS && status == success) {
        status = currContext.map(block_root + size);
        switch (Lde::checkForNewBlock(currContext, block_root + size)) {
            case reachedJump:
                handleEnfOfTrace();
                return reachedJump;

            case reachedConditionalJump:
                handleEnfOfTrace();
                return reachedConditionalJump;

            case reachedReturn:
                handleEnfOfTrace();
                return reachedReturn;

            case reachedCall:
                addResolvedCall(NewFunctionsVec, currContext.resolveJump(block_root + size));

            case noNewBlock:
                break;
            
            case failed:
                return failed;
        }
        prepareNextStep();
    }
    return failed;
}
