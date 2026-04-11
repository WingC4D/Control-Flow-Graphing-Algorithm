#include "function_tree.h"

fnt::ErrorCode FunctionTree::trace() { using enum block::TraceResults;
    TraceContext Context(root, blocksVec.data());
    while (!Context.explorationVec.empty() && Context.blocksCount < block::MAX_INDEX) {
        Context.currentBlock = &blocksVec[Context.explorationVec.back()];
        Context.explorationVec.pop_back();
        Context.blocksCount = static_cast<DWORD>(blocksVec.size());

        if (Context.currentBlock->landmarksPtr->end)
            continue;

        auto result = Context.currentBlock->trace(newFunctionsVec);
        if (checkIfTraced(Context))
            continue;
        switch (result) {
        case reachedJump:
            handleJump(Context.currentBlock->resolveEndAsJump(), Context.blocksCount, Context);
            break;

        case reachedConditionalJump: {
            const BYTE* const resolved_jump          = Context.currentBlock->resolveEndAsJump(),
                * const       next_instruction       = Context.currentBlock->landmarksPtr->end + Context.currentBlock->ldeState->contextsArray.back().getLength();
            const auto        ConditionalJumpContext = next_instruction < resolved_jump ?
                ConditionalJumpCtx{ .shallow_ptr = next_instruction, .deep_ptr = resolved_jump, .shallowIdx = Context.blocksCount | COND_BLOCK_MASK, .deepIdx = Context.blocksCount + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK } :
                ConditionalJumpCtx{ .shallow_ptr = resolved_jump, .deep_ptr = next_instruction, .shallowIdx = Context.blocksCount | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .deepIdx = Context.blocksCount + 1 | COND_BLOCK_MASK };
            handleJump(ConditionalJumpContext.shallow_ptr, ConditionalJumpContext.shallowIdx, Context);
            handleJump(ConditionalJumpContext.deep_ptr, ConditionalJumpContext.deepIdx, Context);
            break;
        }

        case reachedReturn:
            leavesVec.emplace_back(Context.currentBlock->getIndex());
            break;

        case reachedCall:
        case failed:
        case noNewBlock:
            return fnt::failed;
        }
    }
    blocksVec.shrink_to_fit();
    return fnt::success;
}

BOOLEAN FunctionTree::splitBlock(Block& BlockToSplit, const BYTE* splitting_address, std::map<const BYTE*, Block*>& RootsMap) {
#ifdef DEBUG
    if (!BlockToSplit.isInRange(splitting_address))
        return false;
#endif
    if (!splitting_address)
        return false;
    BYTE  iterated_instructions_count = 0,
        original_instructions_count = BlockToSplit.ldeState->instruction_count,
        new_instructions_count = 0;
    for (DWORD new_index = static_cast<DWORD>(blocksVec.size()), last_instruction_length = 0, accumulated_length = 0;
        inst::Context  Context : BlockToSplit.ldeState->contextsArray) {
        if (BlockToSplit.landmarksPtr->root + accumulated_length != splitting_address || !iterated_instructions_count) {
            last_instruction_length = Context.getLength();
            accumulated_length += last_instruction_length;
            iterated_instructions_count++;
            continue;
        }
        blocksVec.emplace_back(splitting_address, BlockToSplit.getIndex(), new_index, BlockToSplit.height + 1);
        Block& NewBlock = blocksVec[new_index];

        for (; iterated_instructions_count + new_instructions_count < original_instructions_count; new_instructions_count++)
            NewBlock.ldeState->contextsArray[new_instructions_count] = BlockToSplit.ldeState->contextsArray[new_instructions_count + iterated_instructions_count];

        NewBlock.resize(new_instructions_count, BlockToSplit.landmarksPtr->end);
        transferUniqueChildren(BlockToSplit, &blocksVec[new_index]);
        BlockToSplit.resize(iterated_instructions_count, splitting_address - last_instruction_length);
        RootsMap[splitting_address] = &blocksVec[new_index];
        break;
    }

    return iterated_instructions_count != original_instructions_count;

}

AddBlock FunctionTree::addBlock(const BYTE* address_to_add, const DWORD index, TraceContext& Context) {
    if (Context.rootsMap.contains(address_to_add))
        return was_traced;
    auto UpperBound = Context.rootsMap.upper_bound(address_to_add);
    if (UpperBound != Context.rootsMap.begin()) {
        Block& PrevBlock = *(--UpperBound)->second;
        if (PrevBlock.isInRange(address_to_add))
            if (splitBlock(PrevBlock, address_to_add, Context.rootsMap))
                return split;
    }
    Context.blocksCount++;
    blocksVec.emplace_back(address_to_add, Context.currentBlock->getIndex(), index, Context.currentBlock->height + 1);
    return added;
}

void FunctionTree::handleJump(const BYTE* resolved_address, const DWORD new_block_idx, TraceContext& TraceContext) {
    if (checkIfTraced(TraceContext))
        return;
    switch (addBlock(resolved_address, new_block_idx, TraceContext)) {
    case added: {
        TraceContext.rootsMap[resolved_address] = &blocksVec[blocksVec.size() - 1];
        TraceContext.currentBlock->flowToVec.emplace_back(blocksVec.size() - 1);
        TraceContext.explorationVec.emplace_back(blocksVec.size() - 1);
        break;
    }
    case was_traced:
        TraceContext.rootsMap.at(resolved_address)->flowFromVec.emplace_back(TraceContext.currentBlock->getIndex());
        break;

    case split:
        break;
    }
}



BOOLEAN FunctionTree::checkIfTraced(TraceContext& Context) {
    const auto NextBlockIterator = Context.rootsMap.upper_bound(Context.currentBlock->landmarksPtr->root);
    if (NextBlockIterator == Context.rootsMap.end())
        return false;

    if (Context.currentBlock->idx == NextBlockIterator->second->idx)
        return false;

    if (!Context.currentBlock->isInRange(NextBlockIterator->second->landmarksPtr->root))
        return false;

    Context.currentBlock->findNewEnd(NextBlockIterator->second->landmarksPtr->root);
    transferUniqueChildren(*Context.currentBlock, NextBlockIterator->second);
    return true;
}

void FunctionTree::transferUniqueChildren(Block& OldParent, Block* const NewParent) {
    if (OldParent.flowToVec.empty()) {
        OldParent.flowToVec.emplace_back(NewParent->getIndex());
        NewParent->flowFromVec.emplace_back(OldParent.getIndex());
        return;
    }
    BOOLEAN transferred_parent = false;
    for (const DWORD child_idx : OldParent.flowToVec) {
        for (BYTE parentsVec_idx = 0; const DWORD parent_idx : blocksVec[child_idx].flowFromVec) {
            if (parent_idx == OldParent.getIndex()) {
                blocksVec[child_idx].flowFromVec[parentsVec_idx] = NewParent->getIndex();
                break;
            }
            parentsVec_idx++;
        }
        transferred_parent = true;
        NewParent->flowToVec.emplace_back(child_idx);
    }
    if (transferred_parent) {
        OldParent.flowToVec.clear();
        OldParent.flowToVec.emplace_back(NewParent->getIndex());
    }
}