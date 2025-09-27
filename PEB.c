#include <windows.h>
#include "shellcode.h"
// #include <winternl.h>
#include <stdio.h>

int main()
{
    #if defined(_M_X64)
        PPEB peb = (PPEB)__readgsdword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    // LDR_DATA_TABLE_ENTRY
    PPEB_LDR_DATA pipi = (PPEB_LDR_DATA)peb->Ldr;
    LIST_ENTRY *ls_ = &pipi->InMemoryOrderModuleList;
    LIST_ENTRY *stop = NULL;
    while(ls_ != stop)
    {
        if(!stop)
            stop = ls_;
        LDR_DATA_TABLE_ENTRY  *entry = (LDR_DATA_TABLE_ENTRY*)ls_->Flink;
        if(entry->FullDllName.Buffer)
            printf("%S\n", entry->FullDllName.Buffer);
        ls_ = ls_->Flink;
    }
}