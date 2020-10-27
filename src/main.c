#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "elfhread.h"

#define BYELLOW  "\033[1;33m"
#define YELLOW   "\033[0;33m"
#define BRED     "\033[1;31m"
#define RED      "\033[0;31m"
#define BBLUE    "\033[1;34m"
#define BLUE     "\033[0;34m"

#define PRINTCOLOR(c, s, ...)         printf(c);printf(s, ##__VA_ARGS__);printf("\033[0m")
#define PRINTYELLOWLABEL(cs, ps, ...) PRINTCOLOR(YELLOW, cs);printf(ps, ##__VA_ARGS__)
#define PRINTREDLABEL(cs, ps, ...)    PRINTCOLOR(RED, cs); printf(ps, ##__VA_ARGS__)
#define PRINTBLUELABEL(cs, ps, ...)   PRINTCOLOR(BLUE, cs); printf(ps, ##__VA_ARGS__)

char*   returnOSABI   (uint8_t  value);
char*   returnEType   (uint16_t value);
char*   returnEndian  (uint8_t  value);
char*   returnMachine (uint16_t value);
char*   returnPType   (uint32_t value);
char*   returnSHType  (uint32_t value);
char*   returnSHFlag  (uint64_t value);

uint8_t* fileHandler  (char* filename);
void describeFileHeader(e_fileheader* fileheader);
void describePHTable(e_fileheader* fileheader, e_programheader** phtable);
void describeSHTable(e_fileheader* fileheader, e_sectionheader** shtable);
void describeHeaders(e_headers* headers);

char* returnOSABI(uint8_t value) {
    switch (value) {
        case 0x00: return "System V";
        case 0x01: return "HP-UX";
        case 0x02: return "NetBSD";
        case 0x03: return "Linux";
        case 0x04: return "GNU Hurd";
        case 0x06: return "Solaris";
        case 0x07: return "AIX";
        case 0x08: return "IRIX";
        case 0x09: return "FreeBSD";
        case 0x0A: return "Tru64";
        case 0x0B: return "Novell Modesto";
        case 0x0C: return "OpenBSD";
        case 0x0D: return "OpenVMS";
        case 0x0E: return "NonStop Kernel";
        case 0x0F: return "AROS";
        case 0x10: return "Fenix OS";
        case 0x11: return "CloudABI";
        case 0x12: return "Status Technologies OpenVOS";
        default:   return "Operating System ABI not found"; 
    }
}

char* returnEType(uint16_t value) {
    switch (value) {
        case 0x00:   return "ET_NONE - No file type";
        case 0x01:   return "ET_REL - Relocatable file";
        case 0x02:   return "ET_EXEC - Executable file";
        case 0x03:   return "ET_DYN - Shared object file";
        case 0x04:   return "ET_CORE - Core file";
        case 0xFE00: return "ET_LOOS - OS specific";
        case 0xFEFF: return "ET_HIOS - OS specific";
        case 0xFF00: return "ET_LOPROC - Processor specific";
        case 0xFFFF: return "EI_HIPROC - Processor specific";
        default:     return "OS/Processor specific";
    }
 }

char* returnEndian(uint8_t value) {
    switch (value) {
        case 1:  return "Little Endian";
        case 2:  return "Big Endian";
        default: return "No endian found %d";
    }
}

char* returnMachine(uint16_t value) {
    switch (value) {
        case 0x00:  return "No specific instruction set";
        case 0x01:  return "AT&T WE 32100";
        case 0x02:  return "SPARC";
        case 0x03:  return "x86";
        case 0x04:  return "Motorola 68000 (M68k)";
        case 0x05:  return "Motorola 88000 (M88k)";
        case 0x06:  return "Intel MCU";
        case 0x07:  return "Intel 80860";
        case 0x08:  return "MIPS";
        case 0x09:  return "IBM_System/370";
        case 0x0A:  return "MIPS RS3000 Little-endian";
        case 0x0B:  return "Reserved for future use";
        case 0x0C:  return "Reserved for future use";
        case 0x0D:  return "Reserved for future use";
        case 0x0E:  return "Hewlett-Packard PA-RISC";
        case 0x0F:  return "Reserved for future use";
        case 0x13:  return "Intel 80960";
        case 0x14:  return "PowerPC";
        case 0x15:  return "PowerPC (64-bit)";
        case 0x16:  return "S390, including S390x";
        case 0x28:  return "ARM (up to ARMv7/Aarch32)";
        case 0x2A:  return "SuperH";
        case 0x32:  return "IA-64";
        case 0x3E:  return "amd64";
        case 0x8C:  return "TMS320C6000 Family";
        case 0xB7:  return "ARM 64-bits (ARMv8/Aarch64)";
        case 0xF3:  return "RISC-V";
        case 0x101: return "WDC 65C816";
        default:    return "Instruction set not found";
    }
} 

char* returnPType(uint32_t value) {
    switch(value) {
        case 0x00000000: return "PT_NULL - Program header table entry unused";
        case 0x00000001: return "PT_LOAD - Loadable segment";
        case 0x00000002: return "PT_DYNAMIC - Dynamic linking information";
        case 0x00000003: return "PT_INTERP - Interpreter information";
        case 0x00000004: return "PT_NOTE - Auxiliary information";
        case 0x00000005: return "PT_SHLIB - reserved";
        case 0x00000006: return "PT_PHDR - segment containing program header table itself";
        case 0x00000007: return "PT_TLS - Thread-Local Storage template";
        case 0x60000000: return "PT_LOOS - OS Specific";
        case 0x6FFFFFFF: return "PT_HIOS - OS Specific"; 
        case 0x70000000: return "PT_LOPROC - Processor Specific";
        case 0x7FFFFFFF: return "PT_HIPROC - Processor Specific";
        default:         return "OS/Processor Specific";
    }
}

char* returnSHType(uint32_t value) {
    switch (value) {
        case 0x0:        return "SHT_NULL - Section header table entry unused";
        case 0x1:        return "SHT_PROGBITS - Program data";
        case 0x2:        return "SHT_SYMTAB - Symbol table";
        case 0x3:        return "SHT_STRTAB - String table";
        case 0x4:        return "SHT_RELA - Relocation entries with addends";
        case 0x5:        return "SHT_HASH - Symbol hash table";
        case 0x6:        return "SHT_DYNAMIC - Dynamic linking information";
        case 0x7:        return "SHT_NOTE - Notes";
        case 0x8:        return "SHT_NOBITS - Program space with no data (bss)";
        case 0x9:        return "SHT_REL - Relocation entries, no addends";
        case 0x0A:       return "SHT_SHLIB - Reserved"; 
        case 0x0B:       return "SHT_DYNSYM - Dynamic linker symbol table";
        case 0x0E:       return "SHT_INIT_ARRAY - Array of constructors";
        case 0x0F:       return "SHT_FINI_ARRAY - Array of destructors";
        case 0x10:       return "SHT_PREINIT_ARRAY - Array of pre-constructors";
        case 0x11:       return "SHT_GROUP - Section group";
        case 0x12:       return "SHT_SYMTAB_SHNDX - Extended section indices";
        case 0x13:       return "SHT_NUM - Number of defined types";
        case 0x60000000: return "SHT_LOOS - OS specific";
        default:         return "OS Specific";
    }
}

char* returnSHFlag(uint64_t value) {
    switch (value) {
        case 0x1:        return "SHF_WRITE - Writable";
        case 0x2:        return "SHF_ALLOC - Occupies memory during execution";
        case 0x4:        return "SHF_EXECINSTR - Executable";
        case 0x10:       return "SHF_MERGE - Might be merged";
        case 0x20:       return "SHF_STRINGS - Contains null-terminated strings";
        case 0x40:       return "SHF_INFO_LINK - 'sh_info' contains SHT index";
        case 0x80:       return "SHF_LINK_ORDER - Preserve order after combining";
        case 0x100:      return "SHF_OS_NONCONFORMING - Non-standard OS specific handling required";
        case 0x200:      return "SHF_GROUP - Section is member of a group";
        case 0x400:      return "SHF_TLS - Section hold thread-local data";
        case 0x0ff00000: return "SHF_MASKOF - OS specific";
        case 0xf0000000: return "SHF_MASKPROC - Processor specific";
        case 0x4000000:  return "SHF_ORDERED - Special ordering requirement (Solaris)";
        case 0x8000000:  return "SHF_EXCLUDE - Section is excluded unless referenced or allocated (Solaris)";
        default:         return "OS/Processor Specific";
    }
}

void describeHeaders(e_headers* headers) {
    describeFileHeader(headers->fileheader);
    describePHTable(headers->fileheader, headers->phtable);
    describeSHTable(headers->fileheader, headers->shtable);
}

void describeSHTable(e_fileheader* fileheader, e_sectionheader** shtable) {
    printf("\n##########################################\n\n");
    PRINTCOLOR(BBLUE, "SECTION HEADER TABLE\n\n");

    for (uint16_t i = 0; i < fileheader->e_shnum; i++) {
        PRINTCOLOR(BBLUE, "Section header %d \n", i++);
        PRINTBLUELABEL("Section name offset: ", "%x \n", shtable[i]->sh_name);
        PRINTBLUELABEL("Header Type: ", "%s \n", returnSHType(shtable[i]->sh_type));
        PRINTBLUELABEL("Flags: ", "%s \n", returnSHFlag(shtable[i]->sh_flags));
        PRINTBLUELABEL("Virtual address: ", "%lx \n", shtable[i]->sh_addr);
        PRINTBLUELABEL("File Image Offset: ", "%lx \n", shtable[i]->sh_offset);
        PRINTBLUELABEL("Section index of associated section: ", "%x \n", shtable[i]->sh_link);
        PRINTBLUELABEL("Extra information: ", "%x \n", shtable[i]->sh_info);
        PRINTBLUELABEL("Requires alignment : ", "%lx \n", shtable[i]->sh_addralign);
        PRINTBLUELABEL("Entry size: ", "%lx \n", shtable[i]->sh_entsize);
        printf("\n");
    }
}

void describePHTable(e_fileheader* fileheader, e_programheader** phtable) {
    printf("\n##########################################\n\n");
    PRINTCOLOR(BRED, "PROGRAM HEADER TABLE\n\n");
    for (uint16_t i = 0; i < fileheader->e_phnum; i++) {
        PRINTCOLOR(BRED, "Program header %d \n", i);
        PRINTREDLABEL("Type of Segment: ", "%s \n", returnPType(phtable[i]->p_type));
        PRINTREDLABEL("Segment-dependent flags: ", "%x \n", phtable[i]->p_flags);
        PRINTREDLABEL("Segment offset: ", "%lx \n", phtable[i]->p_offset);
        PRINTREDLABEL("Segment virtual address: ", "%lx \n", phtable[i]->p_vaddr);
        PRINTREDLABEL("Segment physical address: ", "%lx \n", phtable[i]->p_paddr);
        PRINTREDLABEL("Segment size in file image: ", "%lx (Can be 0) \n", phtable[i]->p_filesz);
        PRINTREDLABEL("Segment size in memory : ", "%lx \n", phtable[i]->p_memsz);
        if (phtable[i]->p_align == 0 || phtable[i]->p_align == 1)  {
            PRINTREDLABEL("Align: ", "No allignment \n");
        }
        else {
            PRINTREDLABEL("Align: ", "%lx \n", phtable[i]->p_align);
        }
        printf("\n");
    }
}

void describeFileHeader(e_fileheader* fileheader) {
    PRINTCOLOR(BYELLOW, "DETAILS FROM FILEHEADER \n \n");

    PRINTYELLOWLABEL("Magic Numbers: ", "%x %x %x %x \n", fileheader->e_ident[EI_MAG0], 
            fileheader->e_ident[EI_MAG1], fileheader->e_ident[EI_MAG2], fileheader->e_ident[EI_MAG3]);
    
    if (fileheader->e_ident[EI_MAG0] != 0x7F && fileheader->e_ident[EI_MAG1] != 0x45 &&
        fileheader->e_ident[EI_MAG2] != 0x4C && fileheader->e_ident[EI_MAG3] != 0x46) {
            perror("Invalid magic number for ELF binary\n");
    }

    PRINTYELLOWLABEL("Format: ", "%d-bits \n", 32*fileheader->e_ident[EI_CLASS]);
    PRINTYELLOWLABEL("Endian: ", "%s \n", returnEndian(fileheader->e_ident[EI_DATA]));
    PRINTYELLOWLABEL("ELF Version: ", "%d \n", fileheader->e_ident[EI_VERSION]);
    PRINTYELLOWLABEL("OSABI: ", "%s (Often set to 0, regardless of target platform) \n", returnOSABI(fileheader->e_ident[EI_OSABI]));
    PRINTYELLOWLABEL("ABI Version: ", "%d \n", fileheader->e_ident[EI_ABIVERSION]);
    PRINTYELLOWLABEL("Object File Type: ", "%s \n", returnEType(fileheader->e_type));
    PRINTYELLOWLABEL("Target Machine: ", "%s \n", returnMachine(fileheader->e_machine));
    PRINTYELLOWLABEL("ELF Version: ", "%d\n", fileheader->e_version);
    PRINTYELLOWLABEL("Program entry point: ", "0x%lx \n", fileheader->e_entry);
    PRINTYELLOWLABEL("Program header table offset: ", "0x%lx \n", fileheader->e_phoff);
    PRINTYELLOWLABEL("Section header table offset: ", "0x%lx \n", fileheader->e_shoff);
    PRINTYELLOWLABEL("File Header Flags: ", "0x%x \n", fileheader->e_flags);
    PRINTYELLOWLABEL("Size of file header: ", "0x%x \n", fileheader->e_ehsize);
    PRINTYELLOWLABEL("Program header table entry size: ", "0x%x \n", fileheader->e_phentsize);
    PRINTYELLOWLABEL("Program header table entries: ", "0x%x \n", fileheader->e_phnum);
    PRINTYELLOWLABEL("Section header table entry size: ", "0x%x \n", fileheader->e_shentsize);
    PRINTYELLOWLABEL("Section header table entries: ", "0x%x \n", fileheader->e_shnum);
    PRINTYELLOWLABEL("Section name entry: ", "0x%x \n", fileheader->e_shstrndx);
}

uint8_t* fileHandler(char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) perror("Problem with opening file\n"); // Check if file exists
    
    fseek(file, 0, SEEK_END);
    unsigned int size = ftell(file);
    fseek(file, 0, SEEK_SET); // Finds the file size

    uint8_t* contents = (uint8_t*) malloc(size);
    fread(contents, sizeof(uint8_t), size, file);
    fclose(file);

    // printf("%s", contents);
    return contents;
}

int main(int argc, char** argv) { 
    char* contents;
    if (argc == 1) {
        printf("Description: Analyzes ELF Binaries");
        printf("Usage: ./elf-analyzer [filename]");
    } if (argc == 2) {
        contents = fileHandler(argv[1]);
    }

    e_headers* headers = handleHeaders(contents);
    describeHeaders(headers);

    return 0;
}