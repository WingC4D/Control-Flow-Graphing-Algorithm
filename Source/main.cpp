#include "main.h"



void main(void) {
	FUNCTION_TREE funcTree(reinterpret_cast<LPBYTE>(GetProcAddress(GetModuleHandleA("KernelBase.dll"), "CreateProcessInternalW")));
	funcTree.Trace();
	std::cin.get();
	return;
}
