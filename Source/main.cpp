#include "main.h"
#include <iostream>

int main() {
    HMODULE hModule = GetModuleHandleW(L"KernelBase.dll");

    if (!hModule)
		return 1;

    LPVOID  target_function = reinterpret_cast<void*>(GetProcAddress(hModule, "CreateProcessInternalW");

    if (!target_function)
		return 2;
	
    FunctionTree FuncTree0(reinterpret_cast<void*>(&CreateFileW)),
                 FuncTree1(target_function);
	
    FuncTree1.trace() == fnt::success ? FuncTree1.print() : std::println("[x] Analysis Failed!");
	FuncTree0.trace() == fnt::success ? FuncTree0.print() : std::println("[x] Analysis Failed!");
	
    std::cin.get();
	return 0;
}