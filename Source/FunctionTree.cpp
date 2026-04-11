#include "function_tree.h"

fnt::ErrorCode FunctionTree::trace() { using enum block::TraceResults;
    TraceContext Context(root);
    while (!Context.explorationVec.empty() && Context.blocksCount < block::MAX_INDEX) {
        Context.currentIdx  = Context.explorationVec.back();
        Context.explorationVec.pop_back();
        Context.blocksCount = static_cast<DWORD>(blocksVec.size());

        if (blocksVec[Context.currentIdx].landmarksPtr->end)
            continue;

        block::TraceResults result = blocksVec[Context.currentIdx].trace(newFunctionsVec);

        if (checkIfTraced(Context))
            continue;

        switch (result) {
            case reachedJump:
                handleJump(blocksVec[Context.currentIdx].resolveEndAsJump(), Context.blocksCount, Context);
                break;

            case reachedConditionalJump: {
                const BYTE* const resolved_jump          = blocksVec[Context.currentIdx].resolveEndAsJump(),
                          * const next_instruction       = blocksVec[Context.currentIdx].landmarksPtr->end + blocksVec[Context.currentIdx].ldeState->contextsArray.back().getLength();
                const auto        ConditionalJumpContext = next_instruction < resolved_jump ?
                    ConditionalJumpCtx{ .shallow_ptr = next_instruction, .deep_ptr = resolved_jump, .shallowIdx = Context.blocksCount | COND_BLOCK_MASK, .deepIdx = Context.blocksCount + 1 | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK } :
                    ConditionalJumpCtx{ .shallow_ptr = resolved_jump, .deep_ptr = next_instruction, .shallowIdx = Context.blocksCount | COND_BLOCK_MASK | C_JUMP_TAKEN_MASK, .deepIdx = Context.blocksCount + 1 | COND_BLOCK_MASK };
                handleJump(ConditionalJumpContext.shallow_ptr, ConditionalJumpContext.shallowIdx, Context);
                handleJump(ConditionalJumpContext.deep_ptr, ConditionalJumpContext.deepIdx, Context);
                break;
            }

            case reachedReturn:
                leavesVec.emplace_back(Context.currentIdx);
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

BOOLEAN FunctionTree::splitBlock(Block& BlockToSplit, const BYTE* splitting_address, std::map<const BYTE*, DWORD>& RootsMap) {
#ifdef DEBUG
    if (!BlockToSplit.isInRange(splitting_address))
        return false;
#endif
    if (!splitting_address)
        return false;
    BYTE  iterated_count = 0,
          original_count = BlockToSplit.ldeState->instruction_count,
          new_count      = 0;
    for (DWORD new_index = static_cast<DWORD>(blocksVec.size()), last_instruction_length = 0, accumulated_length = 0;
        inst::Context  Context : BlockToSplit.ldeState->contextsArray) {
        if (BlockToSplit.landmarksPtr->root + accumulated_length != splitting_address || !iterated_count) {
            last_instruction_length = Context.getLength();
            accumulated_length += last_instruction_length;
            iterated_count++;
            continue;
        }
        blocksVec.emplace_back(splitting_address, BlockToSplit.getIndex(), new_index, BlockToSplit.height + 1);
        Block& NewBlock = blocksVec[new_index];

        for (; iterated_count + new_count < original_count; new_count++)
            NewBlock.ldeState->contextsArray[new_count] = BlockToSplit.ldeState->contextsArray[new_count + iterated_count];

        NewBlock.resize(new_count, BlockToSplit.landmarksPtr->end, BlockToSplit.ldeState->size - accumulated_length);
        transferUniqueChildren(BlockToSplit, new_index);
        BlockToSplit.resize(iterated_count, splitting_address - last_instruction_length, accumulated_length);
        RootsMap[splitting_address] = new_index;
        break;
    }

    return iterated_count != original_count;

}

AddBlock FunctionTree::addBlock(const BYTE* address_to_add, const DWORD index, TraceContext& Context) {
    if (Context.rootsMap.contains(address_to_add))
        return was_traced;
    auto UpperBound = Context.rootsMap.upper_bound(address_to_add);
    if (UpperBound != Context.rootsMap.begin()) {
        Block& PrevBlock = blocksVec[(--UpperBound)->second];
        if (PrevBlock.isInRange(address_to_add))
            if (splitBlock(PrevBlock, address_to_add, Context.rootsMap))
                return split;
    }
    Context.blocksCount++;
    blocksVec.emplace_back(address_to_add, Context.currentIdx, index, blocksVec[Context.currentIdx].height + 1);
    return added;
}

void FunctionTree::handleJump(const BYTE* resolved_address, const DWORD new_block_idx, TraceContext& Context) {
    if (checkIfTraced(Context))
        return;

    switch (addBlock(resolved_address, new_block_idx, Context)) {
        case added: 
            Context.rootsMap[resolved_address] = blocksVec[blocksVec.size() - 1].getIndex();
            blocksVec[Context.currentIdx].flowToVec.emplace_back(blocksVec.size() - 1);
            Context.explorationVec.emplace_back(blocksVec.size() - 1);
            break;
        
        case was_traced:
            blocksVec[Context.rootsMap.at(resolved_address)].flowFromVec.emplace_back(blocksVec[Context.currentIdx].getIndex());
            break;

        case split:
            break;
    }
}



BOOLEAN FunctionTree::checkIfTraced(TraceContext& Context) {
    const auto NextBlockIterator = Context.rootsMap.upper_bound(blocksVec[Context.currentIdx].landmarksPtr->root);
    if (NextBlockIterator == Context.rootsMap.end())
        return false;

    if (Context.currentIdx == NextBlockIterator->second)
        return false;

    if (!blocksVec[Context.currentIdx].isInRange(blocksVec[NextBlockIterator->second].landmarksPtr->root))
        return false;

    blocksVec[Context.currentIdx].findNewEnd(blocksVec[NextBlockIterator->second].landmarksPtr->root);
    transferUniqueChildren(blocksVec[Context.currentIdx], NextBlockIterator->second);
    return true;
}

void FunctionTree::transferUniqueChildren(Block& OldParent, DWORD NewParentIdx) {
    if (OldParent.flowToVec.empty()) {
        OldParent.flowToVec.emplace_back(NewParentIdx);
        blocksVec[NewParentIdx].flowFromVec.emplace_back(OldParent.getIndex());
        return;
    }
    BOOLEAN transferred_parent = false;
    for (const DWORD child_idx : OldParent.flowToVec) {
        for (BYTE parentsVec_idx = 0; const DWORD parent_idx : blocksVec[child_idx].flowFromVec) {
            if (parent_idx == OldParent.getIndex()) {
                blocksVec[child_idx].flowFromVec[parentsVec_idx] = NewParentIdx;
                break;
            }
            parentsVec_idx++;
        }
        transferred_parent = true;
        blocksVec[NewParentIdx].flowToVec.emplace_back(child_idx);
    }
    if (transferred_parent) {
        OldParent.flowToVec.clear();
        OldParent.flowToVec.emplace_back(NewParentIdx);
    }
}