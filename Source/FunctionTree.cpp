#include "function_tree.h"

FunctionTree::ErrorCode FunctionTree::trace() { using namespace block;
    TraceContext Context(root);
    while (!Context.explorationVec.empty() && Context.blocksCount < MAX_INDEX) {
        Context.currIndex  = Context.explorationVec.back();
        Context.explorationVec.pop_back();

        if (blocksVec[Context.currIndex].end)
            continue;

        Context.result = blocksVec[Context.currIndex].trace(newFunctionsVec);

        if (checkIfTraced(Context))
            continue;

        switch (Context.result) { using enum TraceResults;
            case reachedJump:
                handleJump(blocksVec[Context.currIndex].resolveEndAsJump(), Context.blocksCount, Context);
                break;

            case reachedConditionalJump: {
                const BYTE* const resolved_jump          = blocksVec[Context.currIndex].resolveEndAsJump(),
                          * const next_instruction       = blocksVec[Context.currIndex].getNextInstruction();
                const auto        ConditionalJumpContext = next_instruction < resolved_jump ?
                    ConditionalJumpCtx{ .shallow_ptr = next_instruction, .deep_ptr = resolved_jump, .shallowIdx = Context.blocksCount | COND_MASK, .deepIdx = Context.blocksCount + 1 | COND_MASK | COND_TAKEN_MASK } :
                    ConditionalJumpCtx{ .shallow_ptr = resolved_jump, .deep_ptr = next_instruction, .shallowIdx = Context.blocksCount | COND_MASK | COND_TAKEN_MASK, .deepIdx = Context.blocksCount + 1 | COND_MASK };
                handleJump(ConditionalJumpContext.shallow_ptr, ConditionalJumpContext.shallowIdx, Context);
                handleJump(ConditionalJumpContext.deep_ptr, ConditionalJumpContext.deepIdx, Context);
                break;
            }

            case reachedReturn:
                leavesVec.emplace_back(Context.currIndex);
                break;

            case reachedCall:
            case TraceResults::failed:
            case noNewBlock:
                return ErrorCode::failed;
        }
    }
    if (blocksVec.capacity() != blocksVec.size())
        blocksVec.shrink_to_fit();

    if (newFunctionsVec.capacity() != newFunctionsVec.size())
        newFunctionsVec.shrink_to_fit();

    return success;
}

BOOLEAN FunctionTree::splitBlock(DWORD to_split_idx, const BYTE* splitting_address, TraceContext& TraceCtx) {
    if (!splitting_address)
        return false;

    BYTE original_count = blocksVec[to_split_idx].lde.instruction_count,
         iterated_count = 0,
         new_count      = 0;

    for (DWORD last_length = 0, accumulated_length = 0; const inst::Context& Context : blocksVec[to_split_idx].lde.contextsArray) {
        if (blocksVec[to_split_idx].root + accumulated_length != splitting_address || !iterated_count) {
            iterated_count++;
            last_length         = Context.getLength();
            accumulated_length += last_length;
            continue;
        }

        blocksVec.emplace_back(splitting_address, to_split_idx, TraceCtx.blocksCount, blocksVec[to_split_idx].height + 1);
        
        for (; iterated_count + new_count < original_count; new_count++)
            blocksVec.back().lde.contextsArray[new_count] = blocksVec[to_split_idx].lde.contextsArray[new_count + iterated_count];

        TraceCtx.rootsMap[splitting_address] = TraceCtx.blocksCount;
        blocksVec[to_split_idx].resize(iterated_count, splitting_address - last_length, accumulated_length);
        blocksVec.back().resize(new_count, blocksVec[to_split_idx].end, blocksVec[to_split_idx].lde.size - accumulated_length);
        transferUniqueChildren(to_split_idx, TraceCtx.blocksCount);
        break;
    }
    return iterated_count != original_count;
}

FunctionTree::AddBlock FunctionTree::addBlock(const BYTE* address_to_add, const DWORD index, TraceContext& Context) {
    if (Context.rootsMap.contains(address_to_add))
        return was_traced;

    auto UpperBound = Context.rootsMap.upper_bound(address_to_add);
    if (UpperBound != Context.rootsMap.begin()) {
        if (blocksVec[(--UpperBound)->second].isInRange(address_to_add))
            if (splitBlock(UpperBound->second, address_to_add, Context))
                return split;
    }
    blocksVec.emplace_back(address_to_add, Context.currIndex, index, blocksVec[Context.currIndex].height + 1);
    return added;
}

void FunctionTree::handleJump(const BYTE* resolved_address, const DWORD new_block_idx, TraceContext& Context) {
    if (!resolved_address)
        return;

    if (checkIfTraced(Context))
        return;

    switch (addBlock(resolved_address, new_block_idx, Context)) {
        case added:
            Context.rootsMap[resolved_address] = Context.blocksCount;
            blocksVec[Context.currIndex].flowToVec.emplace_back(Context.blocksCount);
            Context.explorationVec.emplace_back(Context.blocksCount);
            Context.blocksCount++;
            break;
        
        case was_traced:
            blocksVec[Context.rootsMap.at(resolved_address)].flowFromVec.emplace_back(Context.currIndex);
            blocksVec[Context.currIndex].flowToVec.emplace_back(Context.rootsMap.at(resolved_address));
            break;

        case split:
            Context.blocksCount++;
            break;
    }
}

BOOLEAN FunctionTree::checkIfTraced(TraceContext& Context) {
    const auto NextBlockIterator = Context.rootsMap.upper_bound(blocksVec[Context.currIndex].root);
    if (NextBlockIterator == Context.rootsMap.end())
        return false;

    if (Context.currIndex == NextBlockIterator->second)
        return false;

    if (!blocksVec[Context.currIndex].isInRange(blocksVec[NextBlockIterator->second].root))
        return false;

    blocksVec[Context.currIndex].findNewEnd(blocksVec[NextBlockIterator->second].root);
    transferUniqueChildren(Context.currIndex, NextBlockIterator->second);
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