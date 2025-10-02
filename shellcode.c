#include "shellcode.h"

//  x86_64-w64-mingw32-gcc .\shellcode.c -O -masm=intel -o shellcode.exe -Wno-int-conversion

inline __attribute__((always_inline)) int  ft_strcmp(const void *dd,const  void *ss)
{
    char    *str = (char*)ss;
    char    *ptr = (char*)dd;
    int i = 0;
    while (str[i] && ptr[i])
    {
        if(str[i] != ptr[i])
            return 0;
        i++;
    }
    return 1;
}

inline __attribute__((always_inline)) void*  Lgetprocadd(HMODULE base_p, char* name)
{
    PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)base_p;
    PIMAGE_OPTIONAL_HEADER  optional_h = (PIMAGE_OPTIONAL_HEADER)((char*)base_p + dos_h->e_lfanew + 0x18);
    PIMAGE_EXPORT_DIRECTORY export_d = (PIMAGE_EXPORT_DIRECTORY)((char*)base_p + optional_h->DataDirectory[0].VirtualAddress);
    DWORD*   names_fadd = (DWORD*)((char*)base_p + export_d->AddressOfNames);
    WORD*   ordinal_ = (WORD*)((char*)base_p + export_d->AddressOfNameOrdinals);
    DWORD*   funs_addr = (DWORD*)((char*)base_p + export_d->AddressOfFunctions);
    int i = 0;
    while (i < export_d->NumberOfNames)
    {
        byte   *n_tmp = (char*)((char*)base_p + names_fadd[i]);
        if(ft_strcmp(name,n_tmp))
        {
            WORD    ord = ordinal_[i];
            DWORD*  target_function = (DWORD*)((char*)base_p + funs_addr[ord]);
            return target_function;
        }
        i++;
    }
}

inline __attribute__((always_inline)) HANDLE ft_LoadLib( char *name)
{
    PEB    *peb;
    
   __asm__ (
    "mov rax, gs:[0x60];"
    : "=r"(peb)
    );
    PPEB_LDR_DATA pipi = (PPEB_LDR_DATA)peb->Ldr;
    LIST_ENTRY    *ls  = &pipi->InMemoryOrderModuleList;
    LIST_ENTRY     *stop = NULL;
    while (stop != ls)
    {
        if(!stop)
            stop = ls;
        LDR_DATA_TABLE_ENTRY    *target = (LDR_DATA_TABLE_ENTRY*)ls->Flink;
        char *str = (char*)target->FullDllName.Buffer;
        if(ft_strcmp(str,name))
            return (HANDLE)(target->InInitializationOrderLinks.Flink);
        ls = ls->Flink;
    }
    return NULL;
}

int main()
{
	PVOID pvStartAddress = NULL;
	PVOID pvEndAddress = NULL;
	
    __asm("StartAddress:;");
	__asm__("and rsp, 0xfffffffffffffff0 ;"
		  "mov rbp, rsp;"
		  "sub rsp, 0x400" 
	);
    CHAR    ker_ll[] = "KERNEL32.dll\0";
    CHAR    BEEEEP[] = "Beep\0";

	typedef BOOL (WINAPI *Beep)(DWORD,DWORD);
    Beep ft_beep= (Beep)Lgetprocadd(ft_LoadLib(ker_ll), BEEEEP);
    ft_beep(550,550);

    __asm("add rsp, 0x400;"); 
	__asm("EndAddress:;");
	
	__asm("lea %0, [rip+StartAddress];"
	:"=r"(pvStartAddress)
	);
	
	__asm("lea %0, [rip+EndAddress];"
	:"=r"(pvEndAddress)
	);

	printf("Start address: %p\n", pvStartAddress);
	printf("End address: %p\n", pvEndAddress);
	
    CONST UCHAR* pStart = (CONST UCHAR*)pvStartAddress;
    CONST UCHAR* pEnd = (CONST UCHAR*)pvEndAddress;

	printf("UCHAR payload[] = {");
    while (pStart < (pEnd-1)) {
        printf("\\x%02x", *pStart);
        pStart++;
    }
	printf("\\x%02x", *pStart);
	printf("};\n");

	
    return 0;
   
}