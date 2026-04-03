#include "..\Headers\main.h"

int main(void) {
	FunctionTree funcTree(reinterpret_cast<LPBYTE>(GetProcAddress(GetModuleHandleA("KernelBase.dll"), "CreateProcessInternalW")));
	funcTree.Trace();
	std::cin.get();
	return 0;
}
