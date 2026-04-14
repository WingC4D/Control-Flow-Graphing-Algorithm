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
                if (no_input == handleJump(blocksVec[Context.currIndex].resolveEndAsJump(), Context.blocksCount, Context))
                    return ErrorCode::failed;
                break;

            case reachedConditionalJump: {
                if (no_input == handleConditionalJump(Context))
                    return ErrorCode::failed;
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
 
BOOLEAN FunctionTree::checkIfTraced(TraceContext& Context) {
    if (Context.rootsMap.size() <= 1)
        return false;

    const auto NextBlockIterator = Context.rootsMap.upper_bound(blocksVec[Context.currIndex].root);
    if (NextBlockIterator == Context.rootsMap.end())
        return false;

    if (Context.currIndex == NextBlockIterator->second)
        return false;

    if (!blocksVec[Context.currIndex].isInRange(blocksVec[NextBlockIterator->second].root))
        return false;

    blocksVec[Context.currIndex].findNewEnd(blocksVec[NextBlockIterator->second].root);
    blocksVec[Context.currIndex].flowToVec.emplace_back(NextBlockIterator->second);
    blocksVec[NextBlockIterator->second].addUniqueParent(Context.currIndex);
    transferUniqueChildren(Context.currIndex, NextBlockIterator->second);
    return true;
}

FunctionTree::AddBlock FunctionTree::handleConditionalJump(TraceContext& Context) {
    ConditionalJumpCtx ConditionalContext(blocksVec[Context.currIndex].resolveEndAsJump(), blocksVec[Context.currIndex].getNextInstruction(), Context.blocksCount);
    switch (handleJump(ConditionalContext.shallow_ptr, ConditionalContext.shallowIdx, Context)) {
        case added:
        case split:
            ConditionalContext.deepIdx++;
            break;

        case was_traced:
            break;

        case no_input:
            return no_input;
    }
    return handleJump(ConditionalContext.deep_ptr, ConditionalContext.deepIdx, Context);
}

FunctionTree::AddBlock FunctionTree::handleJump(const BYTE* resolved_address, const DWORD new_block_idx, TraceContext& Context) {
    if (!resolved_address)
        return no_input;

    switch (addBlock(resolved_address, new_block_idx, Context)) {
        case added:
            Context.rootsMap[resolved_address] = Context.blocksCount;
            blocksVec[Context.currIndex].flowToVec.emplace_back(Context.blocksCount);
            Context.explorationVec.emplace_back(Context.blocksCount);
            Context.blocksCount++;
            return added;

        case was_traced:
            blocksVec[Context.rootsMap.at(resolved_address)].flowFromVec.emplace_back(Context.currIndex);
            blocksVec[Context.currIndex].flowToVec.emplace_back(Context.rootsMap.at(resolved_address));
            return was_traced;

        case split:
            Context.blocksCount++;
            return split;

        case no_input:
            return no_input;
    }
    return no_input;
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

BOOLEAN FunctionTree::splitBlock(DWORD to_split_idx, const BYTE* splitting_address, TraceContext& TraceCtx) {
    if (!splitting_address)
        return false;

    BYTE original_count = blocksVec[to_split_idx].lde.instruction_count,
         iterated_count = 0,
         new_count      = 0;

    for (DWORD last_length = 0, accumulated_length = 0; const inst::Context& Context: blocksVec[to_split_idx].lde.contextsArray) {
        if (blocksVec[to_split_idx].root + accumulated_length != splitting_address || !accumulated_length) {
            iterated_count++;
            last_length         = Context.getLength();
            accumulated_length += last_length;
            continue;
        }
        blocksVec.emplace_back(splitting_address, to_split_idx, TraceCtx.blocksCount, blocksVec[to_split_idx].height + 1);
        blocksVec[TraceCtx.currIndex].flowToVec.emplace_back(TraceCtx.blocksCount);
        blocksVec[TraceCtx.blocksCount].flowFromVec.emplace_back(TraceCtx.currIndex);

        for (; iterated_count + new_count < original_count; new_count++)
            blocksVec.back().lde.contextsArray[new_count] = blocksVec[to_split_idx].lde.contextsArray[new_count + iterated_count];

        TraceCtx.rootsMap[splitting_address] = TraceCtx.blocksCount;
        blocksVec.back().resize(new_count, blocksVec[to_split_idx].end, blocksVec[to_split_idx].lde.size - accumulated_length);
        blocksVec[to_split_idx].resize(iterated_count, splitting_address - last_length, accumulated_length);

        transferUniqueChildren(to_split_idx, TraceCtx.blocksCount);
        break;
    }
    return iterated_count != original_count;
}

void FunctionTree::transferUniqueChildren(DWORD old_parent_idx, DWORD new_parent_idx) {
    if (blocksVec[old_parent_idx].flowToVec.empty()) {
        blocksVec[old_parent_idx].flowToVec.emplace_back(new_parent_idx);
        if (!blocksVec[new_parent_idx].addUniqueParent(old_parent_idx)) {
            if (!changeLeaf(old_parent_idx, new_parent_idx))
                leavesVec.emplace_back(new_parent_idx);
        }
        return;
    }
    BOOLEAN transferred_parent = false;
    for (const DWORD child_idx: blocksVec[old_parent_idx].flowToVec) {
        if (child_idx == new_parent_idx)
            continue;
        for (BYTE parentsVec_idx = 0; const DWORD parent_idx: blocksVec[child_idx].flowFromVec) {
            if (parent_idx == old_parent_idx) {
                blocksVec[child_idx].flowFromVec[parentsVec_idx] = new_parent_idx;
                transferred_parent = true;
                break;
            }
            parentsVec_idx++;
        }
        blocksVec[new_parent_idx].flowToVec.emplace_back(child_idx);
    }
    if (!transferred_parent)
        return;

    blocksVec[old_parent_idx].flowToVec.clear();
    blocksVec[old_parent_idx].flowToVec.emplace_back(new_parent_idx);
}

BOOLEAN FunctionTree::moveBlockData(DWORD old_index, DWORD new_index) {
    if (!blocksVec[old_index].end)
        return false;

    if (blocksVec[old_index].end == blocksVec[new_index].end) {
        blocksVec[old_index].root < blocksVec[new_index].root ?
            blocksVec[old_index].findNewEnd(blocksVec[new_index].root):
            blocksVec[new_index].findNewEnd(blocksVec[old_index].root);
        return true;
    }
    if (!blocksVec[new_index].end && blocksVec[old_index].root < blocksVec[new_index].root) {
        DWORD accumulated_length = 0;
        for (BYTE last_length = 0, new_count = 0, iterated_count = 0, original_count = blocksVec[old_index].lde.instruction_count;
            inst::Context& Context: blocksVec[old_index].lde.contextsArray) {
            if (blocksVec[old_index].root + accumulated_length != blocksVec[new_index].root || !accumulated_length) {
                iterated_count++;
                last_length         = Context.getLength();
                accumulated_length += last_length;
                continue;
            }
            for (; new_count + iterated_count < original_count; new_count++)
                blocksVec[new_index].lde.contextsArray[new_count] = blocksVec[old_index].lde.contextsArray[new_count + iterated_count];

            blocksVec[new_index].resize(new_count, blocksVec[old_index].end, blocksVec[old_index].lde.size - accumulated_length);
            blocksVec[old_index].resize(iterated_count, blocksVec[new_index].root - last_length, accumulated_length);
            transferUniqueChildren(old_index, new_index);
            return new_count != original_count;
        }
    }
    return true;
}
