#include "..\Headers\main.h"

int main() {
	FunctionTree FuncTree(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("KernelBase.dll"), "CreateProcessInternalW")));
	FuncTree.trace() == fTree::success ? FuncTree.print() : std::println("[x] Analysis Failed!");
	std::cin.get();
	return 0;
}