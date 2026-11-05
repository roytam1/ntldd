cl /O2 %~dp0ntlddgui.c %~dp0libntldd.c %1 %2 %3 %4 %5 %6 %7 %8 %9 /link comdlg32.lib gdi32.lib user32.lib kernel32.lib shell32.lib
rem  /Z7 /link /debugtype:both