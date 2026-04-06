#include "..\Headers\main.h"

int main() {
	HMODULE hModule;
	LPVOID target_function;
	if (!(hModule = GetModuleHandleA("KernelBase.dll")))
		return 1;
	if (!(target_function = reinterpret_cast<void*>(GetProcAddress(hModule, "CreateProcessInternalW"))))
		return 2;
	FunctionTree FuncTreeW(reinterpret_cast<void*>(&CreateFileW)), FuncTree(target_function);
	FuncTree.trace()  == fnt::success ? FuncTree.print() : std::println("[x] Analysis Failed!");
	FuncTreeW.trace() == fnt::success ? FuncTreeW.print() : std::println("[x] Analysis Failed!");
	std::cin.get();
	return 0;
}