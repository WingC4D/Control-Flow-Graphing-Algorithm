#include <print>
#include "tests.h"
namespace {
    const IMAGE_OPTIONAL_HEADER* GetOptionalFileHeader(const BYTE* const module_base) {
        if (!module_base)
            return nullptr;

        if (reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base)->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        if (reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base)->e_lfanew)->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return &reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base)->e_lfanew)->OptionalHeader;
    }


    const IMAGE_EXPORT_DIRECTORY* GetImageExportDir(const BYTE* const module_base) {
        auto opt_file_header = GetOptionalFileHeader(module_base);

        if (!opt_file_header)
            return nullptr;

        return reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(module_base + opt_file_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }


    BOOLEAN CheckIfInTextSection(const BYTE* const module_base, const BYTE* const target_function) {
        if (!target_function)
            return false;

        auto opt_file_header = GetOptionalFileHeader(module_base);

        if (!opt_file_header)
            return false;

        return module_base + opt_file_header->BaseOfCode <= target_function && target_function <= module_base + opt_file_header->BaseOfCode + opt_file_header->SizeOfCode;
    }
}

constexpr WCHAR NTDLL[] = L"ntdll.dll";

void RunNtDllSuccessTest() {
    const BYTE* hModule = reinterpret_cast<const BYTE*>(GetModuleHandleW(NTDLL));
    
    if (!hModule)
        if (!(hModule = reinterpret_cast<const BYTE*>(LoadLibraryW(NTDLL)))) {
            std::wprintf(L"[!] Failed to find and load module: \"%s\"\n", NTDLL);
            return std::println("[i] Reported error code: {:#010x}.", GetLastError());
        }
    const IMAGE_EXPORT_DIRECTORY* image_export_dir_ptr = GetImageExportDir(hModule);
    std::map<const BYTE*, DWORD>  all_functions_map{};
    std::vector<FunctionTree>     all_functions_vec{};
    std::vector<DWORD>            exploration_vec(0);
    DWORD i = 0;
    for (; i < image_export_dir_ptr->NumberOfFunctions; i++) { using enum FunctionTree::ErrorCode;
        const BYTE* function_address = hModule + reinterpret_cast<const DWORD*>(hModule + image_export_dir_ptr->AddressOfFunctions)[i];
        if (!CheckIfInTextSection(hModule, function_address))
            continue;
        
        FunctionTree current_function(function_address);
        
        current_function.trace() == success ? std::println("[+] {:s}'s analysis reported success", current_function.name) : std::println("[x] {:s}'s analysis failed!", current_function.name);
        all_functions_vec.emplace_back(std::move(current_function));
        all_functions_map[function_address] = i;
    }
    
    for (auto& function: all_functions_vec) {
        auto new_roots = function.retrieveNewFunctionsRoots();
        for (auto& base_of_new_function: new_roots) { using enum FunctionTree::ErrorCode;
            if (all_functions_map.contains(base_of_new_function))
                continue;

            if (!CheckIfInTextSection(hModule, base_of_new_function))
                continue;
            FunctionTree NewFunction(base_of_new_function);
            NewFunction.trace() == success ? std::println("[+] {:s}'s analysis reported success", NewFunction.name) : std::println("[x] {:s}'s analysis failed!", NewFunction.name);
            all_functions_vec.emplace_back(std::move(NewFunction));
            NewFunction.name = nullptr;
            all_functions_map[base_of_new_function] = i;
            i++;
        }
    }
}


void RunNtDllVerboseTest() {
    const BYTE* hModule = reinterpret_cast<const BYTE*>(GetModuleHandleW(NTDLL));

    if (!hModule)
        if (!(hModule = reinterpret_cast<const BYTE*>(LoadLibraryW(NTDLL)))) {
            std::wprintf(L"[!] Failed to find and load module: \"%s\"\n", NTDLL);
            return std::println("[i] Reported error code: {:#010x}.", GetLastError());
        }
    const IMAGE_EXPORT_DIRECTORY* image_export_dir_ptr = GetImageExportDir(hModule);
    std::map<const BYTE*, DWORD>  all_functions_map{};
    std::vector<FunctionTree>     all_functions_vec{};
    std::vector<DWORD>            exploration_vec(0);
    DWORD i = 0;
    for (; i < image_export_dir_ptr->NumberOfFunctions; i++) {
        using enum FunctionTree::ErrorCode;
        const BYTE* function_address = hModule + reinterpret_cast<const DWORD*>(hModule + image_export_dir_ptr->AddressOfFunctions)[i];
        if (!CheckIfInTextSection(hModule, function_address))
            continue;

        FunctionTree current_function(function_address);

        current_function.trace() == success ? current_function.print() : std::println("\n[x] {:s}'s analysis FAILED!!!\n", current_function.name);
        all_functions_vec.emplace_back(std::move(current_function));
        all_functions_map[function_address] = i;
    }
    for (auto& function : all_functions_vec) {
        auto new_roots = function.retrieveNewFunctionsRoots();
        for (auto& base_of_new_function : new_roots) {
            using enum FunctionTree::ErrorCode;
            if (all_functions_map.contains(base_of_new_function))
                continue;

            if (!CheckIfInTextSection(hModule, base_of_new_function))
                continue;
            FunctionTree NewFunction(base_of_new_function);
            NewFunction.trace() == success ? NewFunction.print() : std::println("[x] {:s}'s analysis failed!", NewFunction.name);
            all_functions_vec.emplace_back(std::move(NewFunction));
            NewFunction.name = nullptr;
            all_functions_map[base_of_new_function] = i;
            i++;
        }
    }
}