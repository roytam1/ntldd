set TCCPATH=F:\tinycc-win32
set TCCLPATH=%TCCPATH%\lib
%TCCPATH%\tcc -O2 %~dp0ntldd.c %~dp0libntldd.c %TCCLPATH%\crtdllold-crt1.c %TCCLPATH%\crtdll-chkstk.S %TCCLPATH%\udivdi3.S %TCCLPATH%\umoddi3.S %TCCLPATH%\libm.c -s -o ntldd-tcc.exe -nostdlib -lkernel32 -lcrtdll
set TCCPATH=
set TCCLPATH=
