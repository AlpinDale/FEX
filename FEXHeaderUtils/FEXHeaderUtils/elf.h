// SPDX-License-Identifier: MIT
#pragma once

#ifdef __APPLE__

#include <cstdint>

// ELF types
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef int32_t  Elf32_Sword;
typedef uint64_t Elf32_Xword;
typedef int64_t  Elf32_Sxword;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint16_t Elf32_Section;

typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;

// ELF identification indices
#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6
#define EI_OSABI    7
#define EI_ABIVERSION 8
#define EI_PAD      9
#define EI_NIDENT   16

// ELF magic numbers
#define ELFMAG0     0x7f
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFMAG      "\177ELF"
#define SELFMAG     4

// ELF classes
#define ELFCLASSNONE    0
#define ELFCLASS32      1
#define ELFCLASS64      2

// ELF data encoding
#define ELFDATANONE     0
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2

// ELF versions
#define EV_NONE         0
#define EV_CURRENT      1

// ELF OS/ABI
#define ELFOSABI_NONE       0
#define ELFOSABI_LINUX      3
#define ELFOSABI_FREEBSD    9

// ELF file types
#define ET_NONE     0
#define ET_REL      1
#define ET_EXEC     2
#define ET_DYN      3
#define ET_CORE     4

// ELF machine types
#define EM_NONE     0
#define EM_386      3
#define EM_X86_64   62
#define EM_ARM      40
#define EM_AARCH64  183

// Program header types
#define PT_NULL     0
#define PT_LOAD     1
#define PT_DYNAMIC  2
#define PT_INTERP   3
#define PT_NOTE     4
#define PT_SHLIB    5
#define PT_PHDR     6
#define PT_TLS      7
#define PT_GNU_EH_FRAME 0x6474e550
#define PT_GNU_STACK    0x6474e551
#define PT_GNU_RELRO    0x6474e552

// Program header flags
#define PF_X        (1 << 0)
#define PF_W        (1 << 1)
#define PF_R        (1 << 2)

// Section header types
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_SHLIB       10
#define SHT_DYNSYM      11
#define SHT_INIT_ARRAY  14
#define SHT_FINI_ARRAY  15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP       17
#define SHT_SYMTAB_SHNDX 18

// Section header flags
#define SHF_WRITE       (1 << 0)
#define SHF_ALLOC       (1 << 1)
#define SHF_EXECINSTR   (1 << 2)
#define SHF_MERGE       (1 << 4)
#define SHF_STRINGS     (1 << 5)
#define SHF_INFO_LINK   (1 << 6)
#define SHF_LINK_ORDER  (1 << 7)
#define SHF_OS_NONCONFORMING (1 << 8)
#define SHF_GROUP       (1 << 9)
#define SHF_TLS         (1 << 10)

// Special section indices
#define SHN_UNDEF       0
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1
#define SHN_COMMON      0xfff2
#define SHN_HIRESERVE   0xffff

// Symbol binding
#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2

// Symbol types
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

// Symbol visibility
#define STV_DEFAULT     0
#define STV_INTERNAL    1
#define STV_HIDDEN      2
#define STV_PROTECTED   3

// Macros
#define ELF32_ST_BIND(val)      (((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val)      ((val) & 0xf)
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))
#define ELF32_ST_VISIBILITY(o)  ((o) & 0x03)

#define ELF64_ST_BIND(val)      ELF32_ST_BIND(val)
#define ELF64_ST_TYPE(val)      ELF32_ST_TYPE(val)
#define ELF64_ST_INFO(bind, type) ELF32_ST_INFO(bind, type)
#define ELF64_ST_VISIBILITY(o)  ELF32_ST_VISIBILITY(o)

#define ELF32_R_SYM(val)        ((val) >> 8)
#define ELF32_R_TYPE(val)       ((val) & 0xff)
#define ELF32_R_INFO(sym, type) (((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i)          ((i) >> 32)
#define ELF64_R_TYPE(i)         ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)  ((((Elf64_Xword) (sym)) << 32) + (type))

// Dynamic tags
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_STRSZ    10
#define DT_SYMENT   11
#define DT_INIT     12
#define DT_FINI     13
#define DT_SONAME   14
#define DT_RPATH    15
#define DT_SYMBOLIC 16
#define DT_REL      17
#define DT_RELSZ    18
#define DT_RELENT   19
#define DT_PLTREL   20
#define DT_DEBUG    21
#define DT_TEXTREL  22
#define DT_JMPREL   23
#define DT_BIND_NOW 24
#define DT_INIT_ARRAY 25
#define DT_FINI_ARRAY 26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH  29
#define DT_FLAGS    30
#define DT_ENCODING 32
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33

// Auxiliary vector types
#define AT_NULL     0
#define AT_IGNORE   1
#define AT_EXECFD   2
#define AT_PHDR     3
#define AT_PHENT    4
#define AT_PHNUM    5
#define AT_PAGESZ   6
#define AT_BASE     7
#define AT_FLAGS    8
#define AT_ENTRY    9
#define AT_NOTELF   10
#define AT_UID      11
#define AT_EUID     12
#define AT_GID      13
#define AT_EGID     14
#define AT_PLATFORM 15
#define AT_HWCAP    16
#define AT_CLKTCK   17
#define AT_SECURE   23
#define AT_BASE_PLATFORM 24
#define AT_RANDOM   25
#define AT_HWCAP2   26
#define AT_EXECFN   31
#define AT_SYSINFO_EHDR 33

// 32-bit ELF header
typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

// 64-bit ELF header
typedef struct {
  unsigned char e_ident[EI_NIDENT];
  Elf64_Half    e_type;
  Elf64_Half    e_machine;
  Elf64_Word    e_version;
  Elf64_Addr    e_entry;
  Elf64_Off     e_phoff;
  Elf64_Off     e_shoff;
  Elf64_Word    e_flags;
  Elf64_Half    e_ehsize;
  Elf64_Half    e_phentsize;
  Elf64_Half    e_phnum;
  Elf64_Half    e_shentsize;
  Elf64_Half    e_shnum;
  Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

// 32-bit program header
typedef struct {
  Elf32_Word    p_type;
  Elf32_Off     p_offset;
  Elf32_Addr    p_vaddr;
  Elf32_Addr    p_paddr;
  Elf32_Word    p_filesz;
  Elf32_Word    p_memsz;
  Elf32_Word    p_flags;
  Elf32_Word    p_align;
} Elf32_Phdr;

// 64-bit program header
typedef struct {
  Elf64_Word    p_type;
  Elf64_Word    p_flags;
  Elf64_Off     p_offset;
  Elf64_Addr    p_vaddr;
  Elf64_Addr    p_paddr;
  Elf64_Xword   p_filesz;
  Elf64_Xword   p_memsz;
  Elf64_Xword   p_align;
} Elf64_Phdr;

// 32-bit section header
typedef struct {
  Elf32_Word    sh_name;
  Elf32_Word    sh_type;
  Elf32_Word    sh_flags;
  Elf32_Addr    sh_addr;
  Elf32_Off     sh_offset;
  Elf32_Word    sh_size;
  Elf32_Word    sh_link;
  Elf32_Word    sh_info;
  Elf32_Word    sh_addralign;
  Elf32_Word    sh_entsize;
} Elf32_Shdr;

// 64-bit section header
typedef struct {
  Elf64_Word    sh_name;
  Elf64_Word    sh_type;
  Elf64_Xword   sh_flags;
  Elf64_Addr    sh_addr;
  Elf64_Off     sh_offset;
  Elf64_Xword   sh_size;
  Elf64_Word    sh_link;
  Elf64_Word    sh_info;
  Elf64_Xword   sh_addralign;
  Elf64_Xword   sh_entsize;
} Elf64_Shdr;

// 32-bit symbol table entry
typedef struct {
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Section st_shndx;
} Elf32_Sym;

// 64-bit symbol table entry
typedef struct {
  Elf64_Word    st_name;
  unsigned char st_info;
  unsigned char st_other;
  Elf64_Section st_shndx;
  Elf64_Addr    st_value;
  Elf64_Xword   st_size;
} Elf64_Sym;

// 32-bit relocation entries
typedef struct {
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
} Elf32_Rel;

typedef struct {
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
  Elf32_Sword   r_addend;
} Elf32_Rela;

// 64-bit relocation entries
typedef struct {
  Elf64_Addr    r_offset;
  Elf64_Xword   r_info;
} Elf64_Rel;

typedef struct {
  Elf64_Addr    r_offset;
  Elf64_Xword   r_info;
  Elf64_Sxword  r_addend;
} Elf64_Rela;

// Dynamic section entry
typedef struct {
  Elf32_Sword   d_tag;
  union {
    Elf32_Word  d_val;
    Elf32_Addr  d_ptr;
  } d_un;
} Elf32_Dyn;

typedef struct {
  Elf64_Sxword  d_tag;
  union {
    Elf64_Xword d_val;
    Elf64_Addr  d_ptr;
  } d_un;
} Elf64_Dyn;

// Note section
typedef struct {
  Elf32_Word    n_namesz;
  Elf32_Word    n_descsz;
  Elf32_Word    n_type;
} Elf32_Nhdr;

typedef struct {
  Elf64_Word    n_namesz;
  Elf64_Word    n_descsz;
  Elf64_Word    n_type;
} Elf64_Nhdr;

// Auxiliary vector entry
typedef struct {
  uint32_t a_type;
  union {
    uint32_t a_val;
  } a_un;
} Elf32_auxv_t;

typedef struct {
  uint64_t a_type;
  union {
    uint64_t a_val;
  } a_un;
} Elf64_auxv_t;

// x86_64 relocation types
#define R_X86_64_NONE       0
#define R_X86_64_64         1
#define R_X86_64_PC32       2
#define R_X86_64_GOT32      3
#define R_X86_64_PLT32      4
#define R_X86_64_COPY       5
#define R_X86_64_GLOB_DAT   6
#define R_X86_64_JUMP_SLOT  7
#define R_X86_64_RELATIVE   8
#define R_X86_64_GOTPCREL   9
#define R_X86_64_32         10
#define R_X86_64_32S        11
#define R_X86_64_16         12
#define R_X86_64_PC16       13
#define R_X86_64_8          14
#define R_X86_64_PC8        15
#define R_X86_64_DTPMOD64   16
#define R_X86_64_DTPOFF64   17
#define R_X86_64_TPOFF64    18
#define R_X86_64_TLSGD      19
#define R_X86_64_TLSLD      20
#define R_X86_64_DTPOFF32   21
#define R_X86_64_GOTTPOFF   22
#define R_X86_64_TPOFF32    23
#define R_X86_64_PC64       24
#define R_X86_64_GOTOFF64   25
#define R_X86_64_GOTPC32    26
#define R_X86_64_SIZE32     32
#define R_X86_64_SIZE64     33
#define R_X86_64_GOTPC32_TLSDESC 34
#define R_X86_64_TLSDESC_CALL 35
#define R_X86_64_TLSDESC    36
#define R_X86_64_IRELATIVE  37

// i386 relocation types (for 32-bit support)
#define R_386_NONE          0
#define R_386_32            1
#define R_386_PC32          2
#define R_386_GOT32         3
#define R_386_PLT32         4
#define R_386_COPY          5
#define R_386_GLOB_DAT      6
#define R_386_JMP_SLOT      7
#define R_386_RELATIVE      8
#define R_386_GOTOFF        9
#define R_386_GOTPC         10
#define R_386_IRELATIVE     42

#else
#include <elf.h>
#endif
