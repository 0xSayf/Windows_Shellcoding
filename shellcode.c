#include "shellcode.h"

// we gonna access the function called Beep from
// kernel32.dll and execute it 

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
            typedef int (ft_beep)(DWORD,DWORD);
            ft_beep* hh_beep = (ft_beep*)target_function; 
            (hh_beep)(5550000,555000);
        }
        i++;
    }
}

inline __attribute__((always_inline)) HANDLE ft_LoadLib( char *name)
{
    PEB    *peb;
    
    __asm__ (
        "movl %%fs:0x30, %%eax"
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
        {
            // printf("hh'\n");
            return (HANDLE)(target->InInitializationOrderLinks.Flink);
        }
        ls = ls->Flink;
    }
    return NULL;
}

int main()
{
    Lgetprocadd(ft_LoadLib("KERNEL32.DLL"), "Beep");
}