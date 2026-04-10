#include "FunctionTree.h"

BOOLEAN Block::isInRange(const BYTE* candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	if (landmarksPtr->root > candidate_address)
		return false;
	if (landmarksPtr->end < candidate_address) 
		return false;
	return true;
}

BOOLEAN Block::isInstructionHead(const LPBYTE candidate_address) const {
	if (!landmarksPtr->end) 
		return false;
	for (DWORD accumulated_length = 0; auto& Context: ldeState->contextsArray) {
		if (landmarksPtr->root + accumulated_length == candidate_address) 
			return true;
		accumulated_length += Context.getLength();
	}
	return false;
}

void Block::resize(const BYTE new_size, const BYTE *new_end_address) const {
	if (!new_size || !new_end_address) 
		return;
	landmarksPtr->end		   = const_cast<BYTE*>(new_end_address);
	ldeState->instruction_count = new_size;
	ldeState->contextsArray.resize(new_size);
}

void Block::findNewEnd(const BYTE *interlacing_root_ptr) const {
	DWORD accumulated_length = 0;
	for (BYTE last_instruction_length = 0, new_instruction_count = 0; auto& Context: ldeState->contextsArray) {
		if (landmarksPtr->root + accumulated_length == interlacing_root_ptr) {
			if (new_instruction_count) 
				resize(new_instruction_count, interlacing_root_ptr - last_instruction_length);
			return;
		}
		last_instruction_length = Context.getLength();
		accumulated_length	   += last_instruction_length;
		new_instruction_count++;
	}
}

BOOLEAN FunctionTree::splitBlock(Block& BlockToSplit, const BYTE* splitting_address, std::map<const BYTE*, Block*>& RootsMap) {
#ifdef DEBUG
	if (!BlockToSplit.isInRange(splitting_address)) 
		return false;
#endif
	if (!splitting_address)
		return false;
	BYTE  iterated_instructions_count = 0,
	      original_instructions_count = BlockToSplit.ldeState->instruction_count;
	for (DWORD new_index = static_cast<DWORD>(blocksVec.size()), last_instruction_length = 0, accumulated_length = 0; 
		 inst::Context  Context: BlockToSplit.ldeState->contextsArray) {
		if (BlockToSplit.landmarksPtr->root + accumulated_length != splitting_address || !iterated_instructions_count) {
			last_instruction_length = Context.getLength();
			accumulated_length	   += last_instruction_length;
			iterated_instructions_count++;
			continue;
		}
		blocksVec.emplace_back(std::make_unique<Block>(splitting_address, BlockToSplit.getIndex(), new_index, BlockToSplit.height + 1));
		Block& NewBlock				  = *blocksVec[new_index];
		BYTE   new_instructions_count = 0;
		for (; iterated_instructions_count + new_instructions_count < original_instructions_count; new_instructions_count++) 
			NewBlock.ldeState->contextsArray[new_instructions_count]	= BlockToSplit.ldeState->contextsArray[new_instructions_count + iterated_instructions_count];
		
		NewBlock.resize(new_instructions_count, BlockToSplit.landmarksPtr->end);
		transferUniqueChildren(BlockToSplit, NewBlock);
		BlockToSplit.resize(iterated_instructions_count, splitting_address - last_instruction_length);
		RootsMap[splitting_address] = blocksVec[new_index].get();
		break;
	}
	return iterated_instructions_count != original_instructions_count;
}

AddBlock FunctionTree::addBlock(const BYTE* address_to_add, const DWORD index, const DWORD parent_index, const DWORD height, std::map<const BYTE*, Block*>& RootsMap) {
	if (RootsMap.contains(address_to_add)) 
		return was_traced;
	auto UpperBound = RootsMap.upper_bound(address_to_add);
	if (UpperBound != RootsMap.begin()) {
		Block& PreviousBlock = *(--UpperBound)->second;
		if (PreviousBlock.isInRange(address_to_add))
			if (splitBlock(PreviousBlock, address_to_add, RootsMap)) 
				return split;
	}
	blocksVec.emplace_back(std::make_unique<Block>(address_to_add, parent_index, index, height));
	return added;
}

fnt::ErrorCode FunctionTree::trace() { using enum blk::TraceResults;
	std::vector<DWORD> ExplorationVec(1);
	std::map		   RootsMap{std::pair{root, blocksVec[0].get()}};
	while (!ExplorationVec.empty()) {
		DWORD  vector_size  =  static_cast<DWORD>(blocksVec.size());
	    Block& CurrentBlock	= *blocksVec[*--ExplorationVec.end()];
		if (vector_size == MAX_BRANCH_INDEX) 
			return fnt::failed;
		ExplorationVec.pop_back();
		if (CurrentBlock.landmarksPtr->end) 
			continue;
		const auto traceResult = CurrentBlock.trace(newFunctionsVec);
		if (checkIfTraced(CurrentBlock, RootsMap)) 
			continue;
		FunctionTreeTraceCtx TraceContext{ .rootsMap = RootsMap, .currentBlock = CurrentBlock, .explorationVec = ExplorationVec };
		switch (traceResult) {
			case reachedJump: 
				handleJump((--CurrentBlock.ldeState->contextsArray.end())->resolveJump(CurrentBlock.landmarksPtr->end), vector_size, TraceContext);
				break;
                
			case reachedConditionalJump: {
                const BYTE* const resolved_jump          = (--CurrentBlock.ldeState->contextsArray.end())->resolveJump(CurrentBlock.landmarksPtr->end),
			              * const next_instruction       = CurrentBlock.landmarksPtr->end + (--CurrentBlock.ldeState->contextsArray.end())->getLength();
				const auto        ConditionalJumpContext = next_instruction < resolved_jump ?
					ConditionalJumpCtx{ .shallow_ptr = next_instruction, .deep_ptr = resolved_jump, .shallowIdx = vector_size | COND_BLOCK_MASK, .deepIdx = vector_size + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK }:
					ConditionalJumpCtx{ .shallow_ptr = resolved_jump, .deep_ptr = next_instruction, .shallowIdx = vector_size | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .deepIdx = vector_size + 1 | COND_BLOCK_MASK };
				handleJump(ConditionalJumpContext.shallow_ptr, ConditionalJumpContext.shallowIdx ,TraceContext);
				handleJump(ConditionalJumpContext.deep_ptr, ConditionalJumpContext.deepIdx, TraceContext);
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

void Block::logIndex() const {//Logs index
	if (idx & COND_BLOCK_MASK) 
		return idx & C_JUMP_TAKEN_MASK ?
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Taken)\n", idx & MAX_BRANCH_INDEX, height) :
			std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Conditional Jump Not Taken)\n", idx & MAX_BRANCH_INDEX, height);

	return height ?
		std::println("[!] Analysing Branch Of Linear Index {:02d} & Of Height: #{:02d} (Non Conditional)\n", idx & 0x00FFFFFF, height):
		std::println("[!] Analysing Root Branch (Non Conditional)\n");
}

void Block::handleEndOfTrace(const BYTE* current_address, LdeState& State) {
    State.contextsArray.resize(State.instruction_count);
    ldeState		  = std::make_unique<LdeState>(State);
    landmarksPtr->end = const_cast<BYTE*>(current_address);
}

blk::TraceResults Block::trace(_Out_ std::vector<const BYTE*>& NewFunctionsVec) const {using enum blk::TraceResults; using enum inst::Context::Status;
	switch (ldeState->traceBlock(landmarksPtr->root, NewFunctionsVec)) {
		case reachedJump: 
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
			return reachedJump;
		
		case reachedConditionalJump: 
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
			return reachedConditionalJump;

		case reachedReturn: 
            landmarksPtr->end = landmarksPtr->root + ldeState->getLastInstHeadOffset();
			return reachedReturn;

	    case noNewBlock:
	    case reachedCall:
		case failed:
            break;
	}
    return failed;
}

blk::TraceResults Block::traceUntil(_Out_ std::vector< const BYTE*>& NewFunctionsVec, const LPBYTE until_address) { using enum blk::TraceResults;
	LdeState State{};
	LPBYTE   reference_ptr = const_cast<BYTE*>(landmarksPtr->root);
	if (reference_ptr == until_address) 
		return failed;
	
	while (State.instruction_count < BLOCK_MAX_INSTRUCTIONS && until_address >= reference_ptr) {
		if (reference_ptr == until_address) {
			handleEndOfTrace(reference_ptr, State);
			return noNewBlock;
		}
		BYTE instruction_length = Lde::mapInstructionLength(reference_ptr, State.currContext, State.status);
		State.prepareNextStep();
		switch (Lde::checkForNewBlock(State.currContext, reference_ptr)) {
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

BOOLEAN FunctionTree::checkIfTraced(Block& JustTracedBlock, std::map<const BYTE*, Block*>& RootsMap) const {
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
	for (DWORD accumulated_length = 0, instruction_count = 0; inst::Context Context: ldeState->contextsArray) {
		Lde::logInstructionAndAddressCtx(landmarksPtr->root + accumulated_length, Context, static_cast<BYTE>(instruction_count));
		accumulated_length += Context.getLength();
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

void FunctionTree::transferUniqueChildren(Block& OldParent, Block& NewParent) const {
	if (OldParent.flowToVec.empty()) {
		OldParent.flowToVec.emplace_back(NewParent.getIndex());
		NewParent.flowFromVec.emplace_back(OldParent.getIndex());
		return;
	}
	BOOLEAN transferred_parent = false;
	for (DWORD child_idx: OldParent.flowToVec) {
		for (BYTE parentsVec_idx = 0; DWORD parent_idx: blocksVec[child_idx]->flowFromVec) {
			if (parent_idx == OldParent.getIndex()) {
				blocksVec[child_idx]->flowFromVec[parentsVec_idx] = NewParent.getIndex();
				break;
			}
			parentsVec_idx++;
		}
		transferred_parent = true;
		NewParent.flowToVec.emplace_back(child_idx);
	}
	if (transferred_parent) {
		OldParent.flowToVec.clear();
		OldParent.flowToVec.emplace_back(NewParent.getIndex());
	}
}

void FunctionTree::handleJump(const BYTE* resolved_address, const DWORD new_block_idx, const FunctionTreeTraceCtx& TraceContext) {
	switch (addBlock(resolved_address, new_block_idx, TraceContext.currentBlock.getIndex(), TraceContext.currentBlock.height + 1, TraceContext.rootsMap)) {
		case added: {
			const DWORD last_index = static_cast<const DWORD>(blocksVec.size() - 1);
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