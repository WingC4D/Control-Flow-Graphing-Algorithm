#pragma once
#ifndef WIN32
    using BYTE    = unsigned char;
    using WORD    = unsigned short;
    using DWORD   = unsigned long;
    using BOOLEAN = BYTE;
    using VOID    = void;
    using LPVOID  = VOID*;
#endif
using QWORD = unsigned long long;