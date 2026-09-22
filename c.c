#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


int main() {
  printf("ffffffffffffffffffffffffffffffffffff\n");
  ShellExecute(NULL, "runas", "cmd.exe", NULL, NULL, SW_SHOWNORMAL);
  while (1);
}   