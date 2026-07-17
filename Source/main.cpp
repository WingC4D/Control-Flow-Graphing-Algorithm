#include "main.h"
#include "tests.h"

constexpr WCHAR MODULE_NAME[]   = L"KERNELBASE.dll";
constexpr CHAR  FUNCTION_NAME[] = "CreateProcessInternalW";
// Currently testing CreateProcessInternalW & CreateFileW (which is redirected intentionally through the IAT.)
int main(int argc, char* argv[]) { using enum FunctionTree::ErrorCode;
    HMODULE hModule = GetModuleHandleW(MODULE_NAME);
    if (!hModule)
        if (!(hModule = LoadLibraryW(MODULE_NAME))) {
            std::wprintf(L"[!] Failed to find and load module: \"%s\"\n", MODULE_NAME);
            std::println("[i] Reported error code: {:#010x}.", GetLastError());
            return 1;
        }
    
    if (argc >= 2) {
        if (!strcmp(argv[1], "--testS")) {
            RunNtDllSuccessTest();
            return 0;
        }

        if (!strcmp(argv[1], "--testV")){
            RunNtDllVerboseTest();
            return 0;
        }
    }
    
    void* target_function = reinterpret_cast<void*>(GetProcAddress(hModule, FUNCTION_NAME));
    
    if (!target_function) {
        std::println();
        return 2;
    }
    
    FunctionTree FuncTree0(reinterpret_cast<void*>(0x00007ffc777fa378)),
                 FuncTree1(target_function);
    /*
    FuncTree1.trace() == success ? FuncTree1.print() : std::println("[x] {:s}'s analysis failed!", FuncTree1.name);
    
    //FuncTree1.print();
   
    auto roots = FuncTree1.retrieveNewFunctionsRoots();
    for (DWORD i = 0; auto tree_root : roots) {
        FunctionTree newFunc(tree_root);
        newFunc.trace() == success ? newFunc.print() : std::println("[x] Analysis of {:s} (Index: {:3d}) Failed!", newFunc.name, i);
        i++;
    }
    */
    
    FuncTree0.trace() == success ? FuncTree0.print() : std::println("[x] {:s}'s analysis failed!", FuncTree0.name);
    auto roots = FuncTree0.retrieveNewFunctionsRoots();
    for (DWORD i = 0; auto tree_root : roots) {
        FunctionTree newFunc(tree_root);
        newFunc.trace() == success ? newFunc.print() : std::println("[x] Analysis of {:s} (Index: {:3d}) Failed!", newFunc.name, i);
        i++;
    }
    

    //FuncTree0.trace() == success ? FuncTree0.print() : std::println("[x] Analysis Failed!");
    
    std::cin.get();
    return 0;
}