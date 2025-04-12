#ifndef __LIBNTLDD_H__
#define __LIBNTLDD_H__

#ifndef _MSC_VER
#include <stdint.h>
#else
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
#endif
#include <windows.h>

#if defined(_MSC_VER) && _MSC_VER < 1500
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR
{
    union
    {
        DWORD AllAttributes;
        struct
        {
            DWORD RvaBased:1;
            DWORD ReservedAttributes:31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;
#endif

#if defined(_MSC_VER) && _MSC_VER < 1200
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  uint64_t            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  uint64_t            SizeOfStackReserve;
  uint64_t            SizeOfStackCommit;
  uint64_t            SizeOfHeapReserve;
  uint64_t            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
#endif

#ifndef GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif

#define NTLDD_VERSION_MAJOR 0
#define NTLDD_VERSION_MINOR 2

struct DepTreeElement;

struct ExportTableItem
{
  void *address;
  char *name;
  WORD ordinal;
  char *forward_str;
  struct ExportTableItem *forward;
  int section_index;
  DWORD address_offset;
};

struct ImportTableItem
{
  uint64_t orig_address;
  uint64_t address;
  char *name;
  int ordinal;
  struct DepTreeElement *dll;
  struct ExportTableItem *mapped;
};

struct DepTreeElement
{
  uint64_t flags;
  char *module;
  char *export_module;
  char *resolved_module;
  void *mapped_address;
  struct DepTreeElement **childs;
  uint64_t childs_size;
  uint64_t childs_len;
  uint64_t imports_len;
  uint64_t imports_size;
  struct ImportTableItem *imports;
  uint64_t exports_len;
  struct ExportTableItem *exports;
};

#define DEPTREE_VISITED    0x00000001
#define DEPTREE_UNRESOLVED 0x00000002
#define DEPTREE_PROCESSED  0x00000004

int ClearDepStatus (struct DepTreeElement *self, uint64_t flags);

void AddDep (struct DepTreeElement *parent, struct DepTreeElement *child);

typedef struct SearchPaths_t
{
    unsigned count;
    char** path;
} SearchPaths;


typedef struct BuildTreeConfig_t
{
    int datarelocs;
    int functionrelocs;
    int recursive;
    int on_self;
    char ***stack;
    uint64_t *stack_len;
    uint64_t *stack_size;
    int machineType;
    int isPE32plus;
    SearchPaths* searchPaths;
} BuildTreeConfig;

int BuildDepTree (BuildTreeConfig* cfg, char *name, struct DepTreeElement *root, struct DepTreeElement *self);


#endif
