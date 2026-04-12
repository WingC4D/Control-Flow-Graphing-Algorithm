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

BOOLEAN FunctionTree::splitBlock(DWORD to_split_idx, const BYTE* splitting_address, std::map<const BYTE*, DWORD>& RootsMap) {
    if (!splitting_address)
        return false;
    BYTE  iterated_count = 0,
          original_count = blocksVec[to_split_idx].ldeState->instruction_count,
          new_count      = 0;
    for (DWORD new_index = static_cast<DWORD>(blocksVec.size()), last_instruction_length = 0, accumulated_length = 0;
        inst::Context  Context : blocksVec[to_split_idx].ldeState->contextsArray) {
        if (blocksVec[to_split_idx].landmarksPtr->root + accumulated_length != splitting_address || !iterated_count) {
            last_instruction_length = Context.getLength();
            accumulated_length += last_instruction_length;
            iterated_count++;
            continue;
        }
        blocksVec.emplace_back(splitting_address, to_split_idx, new_index, blocksVec[to_split_idx].height + 1);
        
        for (; iterated_count + new_count < original_count; new_count++)
            blocksVec[new_index].ldeState->contextsArray[new_count] = blocksVec[to_split_idx].ldeState->contextsArray[new_count + iterated_count];

        blocksVec[new_index].resize(new_count, blocksVec[to_split_idx].landmarksPtr->end, blocksVec[to_split_idx].ldeState->size - accumulated_length);
        transferUniqueChildren(to_split_idx, new_index);
        blocksVec[to_split_idx].resize(iterated_count, splitting_address - last_instruction_length, accumulated_length);
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
        if (blocksVec[(--UpperBound)->second].isInRange(address_to_add))
            if (splitBlock(UpperBound->second, address_to_add, Context.rootsMap))
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
            blocksVec[Context.rootsMap.at(resolved_address)].flowFromVec.emplace_back(Context.currentIdx);
            blocksVec[Context.currentIdx].flowToVec.emplace_back(Context.rootsMap.at(resolved_address));
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
    transferUniqueChildren(Context.currentIdx, NextBlockIterator->second);
    return true;
}

void FunctionTree::transferUniqueChildren(DWORD old_parent_idx, DWORD new_parent_idx) {
    if (blocksVec[old_parent_idx].flowToVec.empty()) {
        blocksVec[old_parent_idx].flowToVec.emplace_back(new_parent_idx);
        blocksVec[new_parent_idx].flowFromVec.emplace_back(old_parent_idx);
        return;
    }
    BOOLEAN transferred_parent = false;
    for (const DWORD child_idx : blocksVec[old_parent_idx].flowToVec) {
        for (BYTE parentsVec_idx = 0; const DWORD parent_idx : blocksVec[child_idx].flowFromVec) {
            if (parent_idx == old_parent_idx) {
                blocksVec[child_idx].flowFromVec[parentsVec_idx] = new_parent_idx;
                break;
            }
            parentsVec_idx++;
        }
        transferred_parent = true;
        blocksVec[new_parent_idx].flowToVec.emplace_back(child_idx);
    }
    if (transferred_parent) {
        blocksVec[old_parent_idx].flowToVec.clear();
        blocksVec[old_parent_idx].flowToVec.emplace_back(new_parent_idx);
    }
}