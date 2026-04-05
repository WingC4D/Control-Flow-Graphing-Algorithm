#include "FunctionTree.h"

BOOLEAN Block::isInRange(const LPBYTE candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	if (landmarksPtr->root > candidate_address)
		return false;
	if (landmarksPtr->end  < candidate_address) 
		return false;
	return true;
}

BOOLEAN Block::isInstructionHead(const LPBYTE candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	for (DWORD accumulated_length = 0; BYTE Context: ldeState->contextsArray) {
		if (landmarksPtr->root + accumulated_length == candidate_address) 
			return true;
		accumulated_length += Lde::getInstructionLengthCtx(Context);
	}
	return false;
}

void Block::resize(const BYTE new_size, const LPBYTE new_end_address) const {
	if (new_size && new_end_address) {
		landmarksPtr->end		   = new_end_address;
		ldeState->instructionCount = new_size;
		ldeState->contextsArray.resize(new_size);
		ldeState->prefixCountArray.resize(new_size);
	}
}

void Block::findNewEnd(const LPBYTE interlacing_root_ptr) const {
	DWORD accumulated_length = 0;
	for (BYTE last_instruction_length = 0, new_instruction_count = 0; BYTE Context: ldeState->contextsArray) {
		if (landmarksPtr->root + accumulated_length == interlacing_root_ptr) {
			if (new_instruction_count) 
				resize(new_instruction_count, interlacing_root_ptr - last_instruction_length);
			return;
		}
		last_instruction_length = Lde::getInstructionLengthCtx(Context);
		accumulated_length	   += last_instruction_length;
		new_instruction_count++;
	}
}

BOOLEAN FunctionTree::splitBlock(Block& BlockToSplit, const LPBYTE splitting_address, std::map<BYTE*, Block*>& RootsMap) {
#ifdef DEBUG
	if (!BlockToSplit.isInRange(splitting_address)) 
		return false;
#endif
	BYTE  iterated_instructions_count = 0,
	      original_instructions_count = BlockToSplit.ldeState->instructionCount,
		 *split_block_root			  = BlockToSplit.landmarksPtr->root;
	for (DWORD new_index = static_cast<DWORD>(blocksVec.size()), last_instruction_length = 0, accumulated_length = 0;
		 BYTE Context: BlockToSplit.ldeState->contextsArray) {
		if (split_block_root + accumulated_length != splitting_address || !iterated_instructions_count) {
			last_instruction_length = Lde::getInstructionLengthCtx(Context);
			accumulated_length	   += last_instruction_length;
			iterated_instructions_count++;
			continue;
		}
		blocksVec.emplace_back(std::make_unique<Block>(splitting_address, BlockToSplit.getIndex(), new_index, BlockToSplit.height + 1));
		Block& NewBlock				  = *blocksVec[new_index];
		BYTE   new_instructions_count = 0;
		for (; iterated_instructions_count + new_instructions_count < original_instructions_count; new_instructions_count++) {
			NewBlock.ldeState->contextsArray[new_instructions_count]	= BlockToSplit.ldeState->contextsArray[new_instructions_count + iterated_instructions_count];
			NewBlock.ldeState->prefixCountArray[new_instructions_count] = BlockToSplit.ldeState->prefixCountArray[new_instructions_count + iterated_instructions_count];
		}
		NewBlock.resize(new_instructions_count, BlockToSplit.landmarksPtr->end);
		transferUniqueChildren(BlockToSplit, NewBlock);
		BlockToSplit.resize(iterated_instructions_count, splitting_address - last_instruction_length);
		RootsMap[splitting_address] = blocksVec[new_index].get();
		break;
	}
	return iterated_instructions_count != original_instructions_count;
}

AddBlock FunctionTree::addBlock(BYTE* const address_to_add, const DWORD new_block_index, const DWORD parent_index, const DWORD height, std::map<BYTE*, Block*>& RootsMap) {
	if (RootsMap.contains(address_to_add)) 
		return  was_traced;
	auto UpperBound = RootsMap.upper_bound(address_to_add);
	if (UpperBound != RootsMap.begin()) {
		Block& PreviousBlock = *(--UpperBound)->second;
		if (PreviousBlock.isInRange(address_to_add)) 
			if (splitBlock(PreviousBlock, address_to_add, RootsMap)) 
				return split;
	}
	blocksVec.emplace_back(std::make_unique<Block>(address_to_add, parent_index, new_block_index, height));
	return added;
}

fnt::ErrorCode FunctionTree::trace() { using enum blk::TraceResults;
	std::vector<DWORD> ExplorationVec(1);
	std::map		   RootsMap{std::pair{root, blocksVec[0].get()}};
	while (!ExplorationVec.empty()) {
		DWORD  current_idx  = *--ExplorationVec.end(),
			   vector_size  =  static_cast<DWORD>(blocksVec.size());
		Block& CurrentBlock	= *blocksVec[current_idx];
		if (vector_size == MAX_BRANCH_INDEX) 
			return fnt::failed;
		ExplorationVec.pop_back();
		if (CurrentBlock.landmarksPtr->end) 
			continue;
		auto traceResult = CurrentBlock.trace(newFunctionsVec);
		if (checkIfTraced(CurrentBlock, RootsMap)) 
			continue;
		FunctionTreeTraceCtx TraceContext{ .rootsMap = RootsMap, .currentBlock = CurrentBlock, .explorationVec = ExplorationVec };
		switch (traceResult) {
			case reachedJump: 
				handleJump(Lde::resolveJump(CurrentBlock.landmarksPtr->end), vector_size, TraceContext);
				break;
			
			case reachedConditionalJump: {
				BYTE *resolved_jump			= Lde::resolveJump(CurrentBlock.landmarksPtr->end),
					 *next_instruction		= CurrentBlock.landmarksPtr->end + Lde::getInstructionLengthCtx(CurrentBlock.ldeState->contextsArray[CurrentBlock.ldeState->instructionCount - 1]);
				auto ConditionalJumpContext = next_instruction < resolved_jump ?
					ConditionalJumpCtx{ .shallowPtr = next_instruction, .deepPtr = resolved_jump, .shallowIdx = vector_size | COND_BLOCK_MASK, .deepIdx = vector_size + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK }:
					ConditionalJumpCtx{ .shallowPtr = resolved_jump, .deepPtr = next_instruction, .shallowIdx = vector_size | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .deepIdx = vector_size + 1 | COND_BLOCK_MASK };
				handleJump(ConditionalJumpContext.shallowPtr, ConditionalJumpContext.shallowIdx ,TraceContext);
				handleJump(ConditionalJumpContext.deepPtr, ConditionalJumpContext.deepIdx, TraceContext);
				break;
			}
			case reachedReturn: 
				leavesVec.push_back(CurrentBlock.getIndex());
				break;
			
			case reachedCall:
			case failed:
			case noNewBlock: 
				return fnt::failed;
		}
 	}
 	return fnt::success;
}

void Block::logIndex() const {
	if (idx & COND_BLOCK_MASK) {
		idx& C_JUMP_TAKEN_MASK ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n", idx & MAX_BRANCH_INDEX, height) :
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n", idx & MAX_BRANCH_INDEX, height);
			return;
	}
	height ?
		std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n", idx & 0x00FFFFFF, height):
		std::println("[!] Analysing Root Branch (Non Conditional)\n");
}

void Block::addResolvedCall(std::vector<unsigned char*>& NewFunctionVec, unsigned char* resolved_address) {
	BOOLEAN was_added = false;
	for (BYTE* stored_func_address: NewFunctionVec) 
		if ((was_added = stored_func_address == resolved_address)) 
			break;
	if (!was_added)
		NewFunctionVec.emplace_back(resolved_address);
}

void Block::handleEndOfTrace(LPBYTE current_address, LdeState& State) {
	State.contextsArray.resize(State.instructionCount);
	State.prefixCountArray.resize(State.instructionCount);
	ldeState		  = std::make_unique<LdeState>(State);
	landmarksPtr->end = current_address;
}

blk::TraceResults Block::trace(_Out_ std::vector<BYTE*>& NewFunctionsVec) { using enum blk::TraceResults;
	LPBYTE	 tracing_address = landmarksPtr->root;
	LdeState State;
	while (State.instructionCount < BLOCK_MAX_INSTRUCTIONS && State.status == success) {
		BYTE instruction_length = Lde::mapInstructionLength(tracing_address, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
		if (!instruction_length) 
			return failed;
		State.prepareForNextStep();
		switch (Lde::checkForNewBlock(State.currInstructionContext, tracing_address)) {
			case reachedJump: 
				handleEndOfTrace(tracing_address, State);
				return reachedJump;
			
			case reachedConditionalJump: 
				handleEndOfTrace(tracing_address, State);
				return reachedConditionalJump;
			
			case reachedCall: 
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(tracing_address));
				break;

			case reachedReturn: 
				handleEndOfTrace(tracing_address, State);
				return reachedReturn;
			
			case failed: 
				return failed;

			case noNewBlock: 
				break;
		}
		tracing_address += instruction_length;
	}
	return failed;
}

blk::TraceResults Block::traceUntil(_Out_ std::vector<LPBYTE>& NewFunctionsVec, _In_ const LPBYTE until_address) { using enum blk::TraceResults;
	LdeState State;
	BYTE	*reference_ptr	    = landmarksPtr->root,
			 instruction_length = 0;
	while (State.instructionCount < BLOCK_MAX_INSTRUCTIONS && until_address >= reference_ptr) {
		if (reference_ptr == until_address && instruction_length) {
			handleEndOfTrace(reference_ptr, State);
			return noNewBlock;
		}
		instruction_length = Lde::mapInstructionLength(reference_ptr, State.currInstructionContext, State.status, State.prefixCountArray[State.instructionCount]);
#ifdef DEBUG
		Lde::logInstructionAndAddress(reference_ptr, State);
#endif
		State.prepareForNextStep();
		switch (Lde::checkForNewBlock(State.currInstructionContext, reference_ptr)) {
			case reachedJump: 
				handleEndOfTrace(reference_ptr, State);
				return reachedJump;
			
			case reachedConditionalJump: 
				handleEndOfTrace(reference_ptr, State);
				return reachedConditionalJump;
			
			case reachedCall: 
				addResolvedCall(NewFunctionsVec, Lde::resolveJump(reference_ptr));
				break;

			case reachedReturn: 
				handleEndOfTrace(reference_ptr, State);
				return reachedReturn;
								
			case noNewBlock:
				break;
			case failed:
				return failed;
		}
		reference_ptr += instruction_length;
	}
	return failed;
}

BOOLEAN FunctionTree::checkIfTraced(Block& JustTracedBlock, std::map<BYTE*, Block*>& RootsMap) const {
	auto NextBlockIterator = RootsMap.upper_bound(JustTracedBlock.landmarksPtr->root);
	if (NextBlockIterator == RootsMap.end())
		return false;
	if (JustTracedBlock.idx == NextBlockIterator->second->idx) 
		return false;
	if (!JustTracedBlock.isInRange(NextBlockIterator->second->landmarksPtr->root))
		return false;
	JustTracedBlock.findNewEnd(NextBlockIterator->second->landmarksPtr->root);
	transferUniqueChildren(JustTracedBlock, *NextBlockIterator->second);
	return true;
}

void Block::print() const {
	if (!landmarksPtr->end) {
		std::println("[!] This Branch Is Not Traced Yet.");
		return;
	}
	for (DWORD accumulated_length = 0, instruction_count = 0; BYTE Context: ldeState->contextsArray) {
		Lde::logInstructionAndAddressCtx(landmarksPtr->root + accumulated_length, Context, static_cast<BYTE>(instruction_count));
		accumulated_length += Lde::getInstructionLengthCtx(Context);
		if (instruction_count >= BLOCK_MAX_INSTRUCTIONS) {
			std::println("Hit an error while printing Block #{:03d}", idx);
			return;
		}
		instruction_count++;
	}
}

DWORD Block::getIndex() const {
	return idx & MAX_BRANCH_INDEX;
}

void FunctionTree::transferUniqueChildren(Block& OldParentBlock, Block& NewParentBlock) const {
	if (OldParentBlock.flowToVec.empty()) {
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
		NewParentBlock.flowFromVec.emplace_back(OldParentBlock.getIndex());
		return;
	}
	BOOLEAN transferred_parent = false;
	for (DWORD  child_idx: OldParentBlock.flowToVec) {
		for (BYTE parents_idx = 0; DWORD dwParentIndex: blocksVec[child_idx]->flowFromVec) {
			if (dwParentIndex == OldParentBlock.getIndex()) {
				blocksVec[child_idx]->flowFromVec[parents_idx] = NewParentBlock.getIndex();
				break;
			}
			parents_idx++;
		}
		transferred_parent = true;
		NewParentBlock.flowToVec.emplace_back(child_idx);
	}
	if (transferred_parent) {
		OldParentBlock.flowToVec.clear();
		OldParentBlock.flowToVec.emplace_back(NewParentBlock.getIndex());
	}
}

void FunctionTree::handleJump(BYTE* const resolved_address, const DWORD new_block_idx, const FunctionTreeTraceCtx& TraceContext) {
	switch (addBlock(resolved_address, new_block_idx, TraceContext.currentBlock.getIndex(), TraceContext.currentBlock.height + 1, TraceContext.rootsMap)) {
		case added: {
			DWORD last_index = static_cast<DWORD>(blocksVec.size()) - 1;
			TraceContext.currentBlock.flowToVec.emplace_back(last_index);
			TraceContext.explorationVec.emplace_back(last_index);
			TraceContext.rootsMap[resolved_address] = blocksVec[last_index].get();
			break;
		}
		case was_traced: 
			TraceContext.rootsMap.at(resolved_address)->flowFromVec.emplace_back(TraceContext.currentBlock.getIndex());
			break;
		
		case split: 
			break;
	}
}