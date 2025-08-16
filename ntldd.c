/*
    ntldd - lists dynamic dependencies of a module

    Copyright (C) 2010 LRN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Code is mostly written after
"An In-Depth Look into the Win32 Portable Executable File Format"
MSDN Magazine articles
*/

#include <windows.h>

#include <imagehlp.h>

#include <winnt.h>

#include <string.h>
#include <stdio.h>

#include "libntldd.h"

#ifdef _MSC_VER
#define I64PF "I64"
#else
#define I64PF "ll"
#endif

typedef BOOL (WINAPI *tW64P)(HANDLE, PBOOL);
typedef BOOL (WINAPI *tFSDisable)(PVOID*);
typedef BOOL (WINAPI *tFSRevert)(PVOID);
typedef UINT (WINAPI *tGetSystemWow64DirectoryA)(LPSTR, UINT);

tW64P pIsWow64Func = NULL;
tFSDisable pDisableFunc = NULL;
tFSRevert pRevertFunc = NULL;
tGetSystemWow64DirectoryA pGetSystemWow64DirectoryA = NULL;

BOOL bIsWow64 = FALSE;

FILE *fp;

void printversion(int print_copyright)
{
  char *platform = "unknown";
#if defined(_M_AMD64) || defined(_M_X64)
  platform = "x86-64";
#elif defined(_M_IA64)
  platform = "IA64";
#elif defined(_M_IX86)
  platform = "x86";
#elif defined(_M_MRX000) || defined(_MIPS_)
  platform = "MIPS";
#elif defined(_M_ARM64)
  platform = "ARM64";
#elif defined(_M_ARM)
  platform = "ARM";
#elif defined(_M_ALPHA) && defined(WIN64)
  platform = "Alpha64";
#elif defined(_M_ALPHA)
  platform = "Alpha";
#elif defined(_M_PPC)
  platform = "PPC";
#endif
  fprintf (fp,"ntldd (%s) %d.%d\n\n", platform, NTLDD_VERSION_MAJOR, NTLDD_VERSION_MINOR);
  if(print_copyright)
    fprintf (fp,"Copyright (C) 2010-2015 LRN\n\
Copyright (C) 2025 Roy Tam (roytam1)\n\
This is free software; see the source for conditions. There is NO\n\
warranty; not event for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
Written by LRN.");
}

void printhelp(char *argv0)
{
  fprintf(fp,"Usage: %s [OPTION]... FILE...\n\
OPTIONS:\n\
--version             Displays version\n\
-v, --verbose         Does not work\n\
-u, --unused          Does not work\n\
-d, --data-relocs     Does not work\n\
-r, --function-relocs Does not work\n\
-R, --recursive       Lists dependencies recursively,\n\
                        eliminating duplicates\n\
-D, --search-dir      Additional search directory\n\
-e, --list-exports    Lists exports of a module (single file only)\n\
-i, --list-imports    Lists imports of modules\n\
--def-output          Print exports in DEF format\n\
--help                Displays this message\n\
\n\
Use -- option to pass filenames that start with `--' or `-'\n\
For bug reporting instructions, please see:\n\
<somewhere>.", argv0);
}

char* mybasename(char* path)
{
    char fullpath[MAX_PATH], *p;
    GetFullPathNameA(path, MAX_PATH, fullpath, &p);
    return p;
}

int PrintImageLinks (int first, int verbose, int unused, int datarelocs, int functionrelocs, struct DepTreeElement *self, int recursive, int list_exports, int def_output, int list_imports, int depth)
{
  uint64_t i;
  int unresolved = 0;
  self->flags |= DEPTREE_VISITED;

  if (def_output)
  {
    fprintf (fp, "LIBRARY %s\n\n\
EXPORTS\n", mybasename(self->module));
    for (i = 0; i < self->exports_len; i++)
    {
      struct ExportTableItem *item = &self->exports[i];

      fprintf (fp,"%s\n", item->name);
    }
    return 0;
  }
  else if (list_exports)
  {
    for (i = 0; i < self->exports_len; i++)
    {
      struct ExportTableItem *item = &self->exports[i];

      fprintf (fp,"%*s[%u] %s (0x%lx)%s%s <%d>\n", depth, depth > 0 ? " " : "", \
          item->ordinal, item->name, item->address_offset, \
          item->forward_str ? " ->" : "", \
          item->forward_str ? item->forward_str : "",
          item->section_index);
    }
    return 0;
  }
  if (self->flags & DEPTREE_UNRESOLVED)  
  {
    if (!first)
      fprintf (fp," => not found\n");
    else
      fprintf (fp, "%s: not found\n", self->module);
    unresolved = 1;
  }

  if (!unresolved && !first && !def_output)
  {
    if (stricmp (self->module, self->resolved_module) == 0)
      fprintf (fp," (0x%p)\n", self->mapped_address);
    else
      fprintf (fp," => %s (0x%p)\n", self->resolved_module,
          self->mapped_address);
  }

  if (list_imports && !def_output)
  {
    if(first) first=0;
    for (i = 0; i < self->imports_len; i++)
    {
      struct ImportTableItem *item = &self->imports[i];

      fprintf (fp,"\t%*s%" I64PF "X %" I64PF "X %3d %s%s %s%s\n", depth, depth > 0 ? " " : "",
          item->orig_address, item->address, item->ordinal,
          item->mapped ? "" : "<UNRESOLVED>",
          item->dll == NULL ? "<MODULE MISSING>" : item->dll->module ? item->dll->module : "<NULL>",
          item->name ? item->name : (item->ordinal != -1 ? "(imported by ordinal)" : "<NULL>"),
          item->is_delayed ? " (delayed)" : "");
    }
  }

  if (unresolved)
    return -1;

  if (first || recursive)
  {
    for (i = 0; i < self->childs_len; i++)
    {
      if (!(self->childs[i]->flags & DEPTREE_VISITED))
      {
        fprintf (fp,"\t%*s%s", depth, depth > 0 ? " " : "", self->childs[i]->module);
        PrintImageLinks (0, verbose, unused, datarelocs, functionrelocs, self->childs[i], recursive, list_exports, def_output, list_imports, depth + 1);
      }
    }
  }
  return 0;
}

int main (int argc, char **argv)
{
  int i;
  int verbose = 0;
  int unused = 0;
  int datarelocs = 0;
  int functionrelocs = 0;
  int skip = 0;
  int files = 0;
  int recursive = 0;
  int list_exports = 0;
  int list_imports = 0;
  int def_output = 0;
  int files_start = -1;
  int files_count = 0;

  DWORD winver, isWin32s;
  HMODULE hKernel;
  PVOID oldValue;

  SearchPaths sp;
  memset(&sp, 0, sizeof (sp));
  sp.path = (char**) calloc (1, sizeof (char*));

  fp = (FILE*)stdout;

  winver = GetVersion();
  isWin32s = ((winver > 0x80000000) && (LOBYTE(LOWORD(winver)) == 3));

  hKernel = GetModuleHandle(TEXT("kernel32.dll"));
  pIsWow64Func = (tW64P) GetProcAddress(hKernel, "IsWow64Process");

  if (pIsWow64Func) {
    pIsWow64Func(GetCurrentProcess(), &bIsWow64);
    if (bIsWow64) {
      pDisableFunc = (tFSDisable) GetProcAddress(hKernel, "Wow64DisableWow64FsRedirection");
      pRevertFunc = (tFSRevert) GetProcAddress(hKernel, "Wow64RevertWow64FsRedirection");
      pGetSystemWow64DirectoryA = (tGetSystemWow64DirectoryA) GetProcAddress(hKernel, "GetSystemWow64DirectoryA");

      if (pGetSystemWow64DirectoryA) {
        char* SysWow64Dir[MAX_PATH];
        pGetSystemWow64DirectoryA((LPSTR)SysWow64Dir, MAX_PATH); // Get SysWow64 path

        sp.count ++;
        sp.path = (char**) realloc(sp.path, sp.count * sizeof(char*));
        sp.path[sp.count - 1] = strdup((char*) SysWow64Dir);
      }
    }

    if ((pDisableFunc) && (pRevertFunc)) {
      pDisableFunc(&oldValue); // Turn off the file system redirector
    }
  }

  if(isWin32s) {
    fp = fopen("ntldd.txt","w");
  }

  for (i = 1; i < argc; i++)
  {
    if (strcmp (argv[i], "--version") == 0)
      printversion (1);
    else if (strcmp (argv[i], "-v") == 0 || strcmp (argv[i], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[i], "-u") == 0 || strcmp (argv[i], "--unused") == 0)
      unused = 1;
    else if (strcmp (argv[i], "-d") == 0 || 
        strcmp (argv[i], "--data-relocs") == 0)
      datarelocs = 1;
    else if (strcmp (argv[i], "-r") == 0 || 
        strcmp (argv[i], "--function-relocs") == 0)
      functionrelocs = 1;
    else if (strcmp (argv[i], "-R") == 0 || 
        strcmp (argv[i], "--recursive") == 0)
      recursive = 1;
    else if (strcmp (argv[i], "-e") == 0 || 
        strcmp (argv[i], "--list-exports") == 0)
      list_exports = 1;
    else if (strcmp (argv[i], "-i") == 0 || 
        strcmp (argv[i], "--list-imports") == 0)
      list_imports = 1;
    else if (strcmp (argv[i], "--def-output") == 0)
      def_output = 1;
    else if ((strcmp (argv[i], "-D") == 0 || strcmp (argv[i], "--search-dir") == 0) && i < argc - 1)
    {
      char *sep, *add_dirs = argv[i+1];
      if (*add_dirs == '"')
          add_dirs++;
      sep = strchr(add_dirs, ';');
      do {
        if (sep)
            *sep = '\0';
        sp.count++;
        sp.path = (char**)realloc(sp.path, sp.count * sizeof(char*));
        if (!sep)
        {
          char* p = strrchr(add_dirs, '"');
          if (p)
            *p = '\0';
        }
        sp.path[sp.count - 1] = strdup(add_dirs);
        add_dirs = sep + 1;
        if (!sep)
            break;
        sep = strchr(add_dirs, ';');
      } while (1);
      i++;
    }
    else if (strcmp (argv[i], "--help") == 0)
    {
      printversion (0);
      printhelp (argv[0]);
      skip = 1;
      break;
    }
    else if (strcmp (argv[i], "--") == 0)
    {
      files = 1;
    }
    else if (strlen (argv[i]) > 1 && argv[i][0] == '-' && (argv[i][1] == '-' ||
        strlen (argv[i]) == 2) && !files)
    {
      fprintf (fp, "Unrecognized option `%s'\n\
Try `ntldd --help' for more information\n", argv[i]);
      skip = 1;
      break;
    }
    else if (files_start < 0)
    {
      skip = 0;
      files_start = i;
      break;
    }
  }
  if (!skip && files_start > 0)
  {
    int multiple;
    struct DepTreeElement root;
    files_count = argc - files_start;
    sp.count += files_count;
    sp.path = (char**) realloc(sp.path, sp.count * sizeof(char*));
    for (i = 0; i < files_count; ++i)
    {
      char *p, buff[MAX_PATH];
      memset(buff, 0, MAX_PATH);
      GetFullPathNameA(argv[files_start+i], MAX_PATH, buff, &p);
      *p = '\0';

      sp.path[sp.count - files_count + i] = strdup(buff);
    }
    multiple = files_start + 1 < argc;
    memset (&root, 0, sizeof (struct DepTreeElement));
    for (i = files_start; i < argc; i++)
    {
      char **stack = NULL;
      uint64_t stack_len = 0;
      uint64_t stack_size = 0;
      BuildTreeConfig cfg;
      struct DepTreeElement *child = (struct DepTreeElement *) malloc (sizeof (struct DepTreeElement));
      memset (child, 0, sizeof (struct DepTreeElement));
      child->module = strdup (argv[i]);
      AddDep (&root, child);
      memset(&cfg, 0, sizeof(cfg));
      cfg.machineType = -1;
      cfg.on_self = 0;
      cfg.isPE32plus = 0;
      cfg.datarelocs = datarelocs;
      cfg.recursive = recursive;
      cfg.functionrelocs = functionrelocs;
      cfg.stack = &stack;
      cfg.stack_len = &stack_len;
      cfg.stack_size = &stack_size;
      cfg.searchPaths = &sp;
      BuildDepTree (&cfg, argv[i], &root, child);
    }
    ClearDepStatus (&root, DEPTREE_VISITED | DEPTREE_PROCESSED);
    for (i = files_start; i < argc; i++)
    {
      if (multiple)
        fprintf (fp,"%s:\n", argv[i]);
      PrintImageLinks (1, verbose, unused, datarelocs, functionrelocs, root.childs[i - files_start], recursive, list_exports, def_output, list_imports, 0);
    }
  }

  if ((pDisableFunc) && (pRevertFunc)) {
    pRevertFunc(oldValue); // Restore the file system redirector
  }

  if(isWin32s) {
    fclose(fp);
    WinExec("notepad ntldd.txt", SW_NORMAL);
    Sleep(3000);
    remove("ntldd.txt");
  }

  return 0;
}
