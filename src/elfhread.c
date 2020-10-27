#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "elfhread.h"

#define COMBINEWORD(index)    combineBytes(2, contents, index, fileheader->e_ident[EI_DATA])
#define COMBINEDWORD(index)   combineBytes(4, contents, index, fileheader->e_ident[EI_DATA])
#define COMBINEQWORD(index)   combineBytes(8, contents, index, fileheader->e_ident[EI_DATA])
#define COMBINESYSSIZE(index) combineBytes(4*fileheader->e_ident[EI_CLASS], contents, index, fileheader->e_ident[EI_DATA])

#define PHOFFSET(off) fileheader->e_phoff + (i*fileheader->e_phentsize) + off
#define SHOFFSET(off) fileheader->e_shoff + (i*fileheader->e_shentsize) + off

uint64_t combineBytes (unsigned int bytes, uint8_t* contents, unsigned int index, uint8_t endianness);

uint64_t combineBytes(unsigned int bytes, uint8_t* contents, unsigned int index, uint8_t endianness) {
    uint64_t lilresult = 0;
    uint64_t bigresult = 0;
    for (unsigned int i = 0; i < bytes; i++) {
        lilresult |= contents[index + abs(i-3)] << 8*i;
        bigresult |= contents[index + i] << 8*i;
    }

    if (endianness == 1) return bigresult; // if it is big endian
    else                 return lilresult; // if it is little endian
}

e_headers* handleHeaders(char* contents) {
    e_headers* headers = (e_headers*) malloc(sizeof(e_headers));

    headers->fileheader = handleFileHeader(contents);
    headers->phtable = handlePHTable(contents, headers->fileheader);
    headers->shtable = handleSHTable(contents, headers->fileheader);

    return headers;
}

e_sectionheader** handleSHTable(char* contents, e_fileheader* fileheader) {
    e_sectionheader** shtable = (e_sectionheader**) malloc(sizeof(e_sectionheader*));

    for (uint16_t i = 0; i < fileheader->e_shnum; i++) {
        shtable[i] = (e_sectionheader*) malloc(sizeof(e_sectionheader));

        shtable[i]->sh_name = COMBINEDWORD(SHOFFSET(0x00));

        shtable[i]->sh_type = COMBINEDWORD(SHOFFSET(0x04));
        shtable[i]->sh_flags = COMBINESYSSIZE(SHOFFSET(0x08));
        if (fileheader->e_ident[EI_CLASS] == 1) {
            shtable[i]->sh_addr = COMBINESYSSIZE(SHOFFSET(0x0C));
            shtable[i]->sh_offset = COMBINESYSSIZE(SHOFFSET(0x10));
            shtable[i]->sh_size = COMBINESYSSIZE(SHOFFSET(0x14));
            shtable[i]->sh_link = COMBINEDWORD(SHOFFSET(0x18));
            shtable[i]->sh_info = COMBINEDWORD(SHOFFSET(0x1C));
            shtable[i]->sh_addralign = COMBINESYSSIZE(SHOFFSET(0x20));
            shtable[i]->sh_entsize = COMBINESYSSIZE(SHOFFSET(0x24));
        }
        else {
            shtable[i]->sh_addr = COMBINESYSSIZE(SHOFFSET(0x10));
            shtable[i]->sh_offset = COMBINESYSSIZE(SHOFFSET(0x18));
            shtable[i]->sh_size = COMBINESYSSIZE(SHOFFSET(0x20));
            shtable[i]->sh_link = COMBINEDWORD(SHOFFSET(0x28));
            shtable[i]->sh_info = COMBINEDWORD(SHOFFSET(0x2C));
            shtable[i]->sh_addralign = COMBINESYSSIZE(SHOFFSET(0x30));
            shtable[i]->sh_entsize = COMBINESYSSIZE(SHOFFSET(0x38));
        }
    }
    return shtable;
}

e_programheader** handlePHTable(char* contents, e_fileheader* fileheader) {
    e_programheader** phtable = (e_programheader**) malloc(fileheader->e_phnum * sizeof(e_programheader*));

    for (uint16_t i = 0; i < fileheader->e_phnum; i++) {
        phtable[i] = (e_programheader*) malloc(sizeof(e_programheader));
        phtable[i]->p_type = COMBINEDWORD(PHOFFSET(0x00));
        if (fileheader->e_ident[EI_CLASS] == 1) {
            phtable[i]->p_offset = COMBINESYSSIZE(PHOFFSET(0x04));
            phtable[i]->p_vaddr = COMBINESYSSIZE(PHOFFSET(0x08));
            phtable[i]->p_paddr = COMBINESYSSIZE(PHOFFSET(0x0C));
            phtable[i]->p_filesz = COMBINESYSSIZE(PHOFFSET(0x10));
            phtable[i]->p_memsz = COMBINESYSSIZE(PHOFFSET(0x14));
            phtable[i]->p_flags = COMBINEDWORD(PHOFFSET(0x18));
            phtable[i]->p_align = COMBINESYSSIZE(PHOFFSET(0x1C));
        } else {
            phtable[i]->p_flags = COMBINEDWORD(PHOFFSET(0x04));
            phtable[i]->p_offset = COMBINESYSSIZE(PHOFFSET(0x08));
            phtable[i]->p_vaddr = COMBINESYSSIZE(PHOFFSET(0x10));
            phtable[i]->p_paddr = COMBINESYSSIZE(PHOFFSET(0x18));
            phtable[i]->p_filesz = COMBINESYSSIZE(PHOFFSET(0x20));
            phtable[i]->p_memsz = COMBINESYSSIZE(PHOFFSET(0x28));
            phtable[i]->p_align = COMBINESYSSIZE(PHOFFSET(0x30));
        }
    }
    return phtable;
}

e_fileheader* handleFileHeader(char* contents) {
    e_fileheader* fileheader = (e_fileheader*) malloc(sizeof(e_fileheader));

    for (unsigned int i = 0x00; i <= 0x09; i++) {
        fileheader->e_ident[i] = contents[i];
    }

    fileheader->e_type = COMBINEWORD(0x10);
    fileheader->e_machine = COMBINEWORD(0x12);
    fileheader->e_version = COMBINEDWORD(0x14);

    fileheader->e_entry = COMBINESYSSIZE(0x18);

    if (fileheader->e_ident[EI_CLASS] == 1) {
        fileheader->e_phoff = COMBINESYSSIZE(0x1C);
        fileheader->e_shoff = COMBINESYSSIZE(0x20);

        fileheader->e_flags = COMBINEDWORD(0x24);
        fileheader->e_ehsize = COMBINEWORD(0x28);
        fileheader->e_phentsize = COMBINEWORD(0x2A);
        fileheader->e_phnum = COMBINEWORD(0x2C);
        fileheader->e_shentsize = COMBINEWORD(0x2E);
        fileheader->e_shnum = COMBINEWORD(0x30);
        fileheader->e_shstrndx = COMBINEWORD(0x32);
    } else {
        fileheader->e_phoff = COMBINESYSSIZE(0x20);
        fileheader->e_shoff = COMBINESYSSIZE(0x28);

        fileheader->e_flags = COMBINEDWORD(0x30);
        fileheader->e_ehsize = COMBINEWORD(0x34);
        fileheader->e_phentsize = COMBINEWORD(0x36);
        fileheader->e_phnum = COMBINEWORD(0x38);
        fileheader->e_shentsize = COMBINEWORD(0x3A);
        fileheader->e_shnum = COMBINEWORD(0x3C);
        fileheader->e_shstrndx = COMBINEWORD(0x3E);
    }

    return fileheader;
}