typedef enum {
    EI_MAG0,
    EI_MAG1,
    EI_MAG2,
    EI_MAG3,
    EI_CLASS,
    EI_DATA,
    EI_VERSION,
    EI_OSABI,
    EI_ABIVERSION,
    EI_PAD,
    EI_IDENT_END
} e_ident_val;

typedef uint64_t uintAddr_t;
typedef uint64_t uintOffS_t;

typedef struct {
    uint8_t    e_ident[EI_IDENT_END];
    uint16_t   e_type;
    uint16_t   e_machine;
    uint32_t   e_version;
    uintAddr_t e_entry; // 32 or 64 bit
    uintOffS_t e_phoff; // 32 or 64 bit
    uintOffS_t e_shoff; // 32 or 64 bit
    uint32_t   e_flags; 
    uint16_t   e_ehsize;
    uint16_t   e_phentsize;
    uint16_t   e_phnum;
    uint16_t   e_shentsize;
    uint16_t   e_shnum;
    uint16_t   e_shstrndx;
} e_fileheader;

typedef struct {
    uint32_t   p_type;
    uint32_t   p_flags;
    uintOffS_t p_offset; // 32 or 64 bit
    uintAddr_t p_vaddr;  // 32 or 64 bit
    uintAddr_t p_paddr;  // 32 or 64 bit
    uint64_t   p_filesz; // 32 or 64 bit
    uint64_t   p_memsz;  // 32 or 64 bit
    uint64_t   p_align;  // 32 or 64 bit
} e_programheader;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;     // 32 or 64 bit
    uintAddr_t sh_addr;      // 32 or 64 bit
    uintOffS_t sh_offset;    // 32 or 64 bit
    uint64_t   sh_size;      // 32 or 64 bit
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign; // 32 or 64 bit
    uint64_t   sh_entsize;   // 32 or 64 bit
} e_sectionheader;

typedef struct {
    uint8_t bytes;
    e_fileheader* fileheader;
    e_programheader** phtable;
    e_sectionheader** shtable;
} e_headers;

e_fileheader* handleFileHeader(char* contents);
e_programheader** handlePHTable(char* contents, e_fileheader* fileheader);
e_sectionheader** handleSHTable(char* contents, e_fileheader* fileheader);