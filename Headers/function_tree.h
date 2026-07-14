#pragma once
#include <windows.h>
#include <format>
#include <map>
#include "block.h"


#ifdef _WIN32
    #include <winternl.h>
    constexpr DWORD INVALID_MODULE_SIZE = 0xFFFFFFFF;
#endif
constexpr WORD  BASE_BLOCK_RESERVE_SIZE = 0x0400,
                NEW_FUNCTIONS_BASE_SIZE = 0x0004,
                SIZE_OF_UNKNOWN_NAME    = 24;

struct ConditionalJumpCtx {
    const BYTE* shallow_ptr,
              * deep_ptr;
	DWORD	    shallowIdx,
			    deepIdx;

    ConditionalJumpCtx(const BYTE* resolved_address, const BYTE* next_address, DWORD current_block_count) { using namespace block;
        if (next_address < resolved_address) {
            shallow_ptr = next_address;
            deep_ptr    = resolved_address;
            shallowIdx  = current_block_count | COND_MASK;
            deepIdx     = current_block_count | COND_MASK | COND_TAKEN_MASK;
            return;
        }
        shallow_ptr = resolved_address ;
        deep_ptr    = next_address;
        shallowIdx  = current_block_count | COND_MASK | COND_TAKEN_MASK;
        deepIdx     = current_block_count | COND_MASK;
    }
};

namespace block {
    enum TraceResults: BYTE;
}

class FunctionTree {
public:
    enum ErrorCode : BYTE {
        success,
        failed
    };
    FunctionTree(const VOID *lpFunctionRoot) : root(static_cast<const BYTE*>(lpFunctionRoot)), name(resolveName()) {
        blocksVec.reserve(BASE_BLOCK_RESERVE_SIZE);
        blocksVec.emplace_back(root);
        newFunctionsVec.reserve(NEW_FUNCTIONS_BASE_SIZE);
#ifdef _WIN32
#endif
    }

    ErrorCode trace();

    void print() const {
        for (const auto& block : blocksVec) {
            block.logIndex(name);
            block.logFromAndToVectors(name);
            block.logInstructionBytesAndAddresses();
        }
    }
    
    std::vector<const BYTE*> retrieveNewFunctionsRoots() {
        return newFunctionsVec;
    }

private:
    const BYTE*              root;
	std::vector<Block>       blocksVec;
	std::vector<const BYTE*> newFunctionsVec;
	std::vector<DWORD>		 leavesVec{};

public:
    LPCSTR                   name;
    
private:
    struct TraceContext {
        std::map<const BYTE*, DWORD> rootsMap;
        std::vector<DWORD>           explorationVec;
        DWORD                        blocksCount,
                                     currIndex;
        block::TraceResults          result; 

        TraceContext(const BYTE* root_address): rootsMap(std::map{ std::pair{ root_address, static_cast<DWORD>(0) } }), explorationVec(1) {
            explorationVec.reserve(BASE_BLOCK_RESERVE_SIZE);
            currIndex    = 0;
            blocksCount  = 1;
            result       = block::TraceResults::noNewBlock;
        }
    };

#ifdef _WIN32
    LPCSTR resolveName() const {

        const BYTE* pModuleBase = getContainingModule();
        
        if (!pModuleBase)
            return nullptr;
        
        auto pImageExportDir = getImageExportDirectory(pModuleBase);

        if (!pImageExportDir)
            return nullptr;

        for (DWORD i = 0; i < pImageExportDir->NumberOfNames; i++) {
            if (pModuleBase + reinterpret_cast<const DWORD*>(pModuleBase + pImageExportDir->AddressOfFunctions)[reinterpret_cast<const WORD*>(pModuleBase + pImageExportDir->AddressOfNameOrdinals)[i]] == root)
                return reinterpret_cast<LPCSTR>(pModuleBase + reinterpret_cast<const DWORD*>(pModuleBase + pImageExportDir->AddressOfNames)[i]);
        }
        LPSTR _format = static_cast<LPSTR>(malloc(SIZE_OF_UNKNOWN_NAME));
        memset(_format, 0, SIZE_OF_UNKNOWN_NAME);
        std::format_to(_format, "Sub_{:#14x}", reinterpret_cast<const DWORD64>(root));
        return _format;
    }
    const BYTE* getContainingModule() const {
        auto  pHeadEntry = reinterpret_cast<PPEB>(__readgsqword(0x60))->Ldr->InMemoryOrderModuleList.Flink,
              pCurrEntry = pHeadEntry;
        do {
            DWORD module_size = getModuleSize(static_cast<BYTE*>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry)->Reserved2[0]));
            if (module_size == INVALID_MODULE_SIZE) {
                pCurrEntry = pCurrEntry->Flink;
                continue;
            }
            if (reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry)->Reserved2[0] < root && static_cast<BYTE*>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry)->Reserved2[0]) + module_size > root) {
                return static_cast<BYTE*>(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pCurrEntry)->Reserved2[0]);
            }
            pCurrEntry = pCurrEntry->Flink;
        } while (pCurrEntry != pHeadEntry);
        return nullptr;
    }
    static DWORD getModuleSize(const BYTE* const pModuleBase) {
        if (!pModuleBase)
            return INVALID_MODULE_SIZE;
        
        if (reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_magic != IMAGE_DOS_SIGNATURE)
            return INVALID_MODULE_SIZE;

        if (reinterpret_cast<const IMAGE_NT_HEADERS*>(pModuleBase + reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_lfanew)->Signature != IMAGE_NT_SIGNATURE)
            return INVALID_MODULE_SIZE;
            
        return reinterpret_cast<const IMAGE_NT_HEADERS*>(pModuleBase + reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_lfanew)->OptionalHeader.SizeOfImage;
    }

    static const IMAGE_EXPORT_DIRECTORY* getImageExportDirectory(const BYTE* const pModuleBase) {
        if (!pModuleBase)
            return nullptr;

        if (reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        if (reinterpret_cast<const IMAGE_NT_HEADERS*>(pModuleBase + reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_lfanew)->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(pModuleBase + reinterpret_cast<const IMAGE_NT_HEADERS*>(pModuleBase + reinterpret_cast<const IMAGE_DOS_HEADER*>(pModuleBase)->e_lfanew)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
#endif

    enum AddBlock : BYTE {
        was_traced = 0,
        added      = 1,
        split      = 2,
        no_input   = 3
    };

    BOOLEAN splitBlock(DWORD to_split_idx, const BYTE* splitting_address, TraceContext& TraceCtx);

	AddBlock addBlock(const BYTE *address_to_add, DWORD index, TraceContext& Context);

    BOOLEAN changeLeaf(DWORD old_index, DWORD new_index) {
        for (DWORD& leaf: leavesVec)
            if (leaf == old_index) {
                leaf = new_index;
                return true;
            }
        return false;
    }

    void addLeaf(DWORD leaf_index) {
        for (DWORD leaf: leavesVec)
            if (leaf_index == leaf)
                return;
        leavesVec.emplace_back(leaf_index);
    }

	void transferUniqueChildren(DWORD old_parent_idx, DWORD new_parent_idx);

	inline BOOLEAN checkIfTraced(TraceContext& Context);

	AddBlock handleJump(const BYTE* resolved_address, DWORD new_block_idx, TraceContext& Context);

    AddBlock handleConditionalJump(TraceContext& Context);
};