cl /O2 -D_AXP64_=1 -D_ALPHA64_=1 -DALPHA=1 -DWIN64 -D_WIN64 -DWIN32 -D_WIN32  -Wp64 -W4 -Ap64 %~dp0ntldd.c %~dp0libntldd.c
rem  /Z7 /link /debugtype:both
