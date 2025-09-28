#include <stdio.h>
#include <stdlib.h>
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned char BYTE;

typedef struct _IMAGE_SECTION_HEADER 
{
  BYTE    Name[8];
  union 
  {
          DWORD   PhysicalAddress;
          DWORD   VirtualSize;
  } Misc;
  DWORD   VirtualAddress;
  DWORD   SizeOfRawData;
  DWORD   PointerToRawData;
  DWORD   PointerToRelocations;
  DWORD   PointerToLinenumbers;
  WORD    NumberOfRelocations;
  WORD    NumberOfLinenumbers;
  DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

int main ()
{
    FILE  *file = fopen("shellcode.exe", "rb");
    if(!file)
        return 0;
    DWORD elfanew;
    IMAGE_SECTION_HEADER sections;
    fseek(file,0x3C,SEEK_SET);
    fread(&elfanew,sizeof(DWORD), 1 ,file);
    fseek(file,elfanew + 0xF8,SEEK_SET);
    fread(&sections,sizeof(IMAGE_SECTION_HEADER), 1 ,file);
    DWORD   text_seg = sections.PointerToRawData;
    char *ptr = malloc(sections.SizeOfRawData + 1);
    fseek(file,text_seg,SEEK_SET);
    fread(ptr,sections.SizeOfRawData, 1 ,file);
    int i = 0;
    while (i < sections.SizeOfRawData)
    {
        if(i % 10 == 0)
            printf("\"\n\"");
        printf("\\x");
        printf("%X", ptr[i] & 0xff);
        i++;
    }
}