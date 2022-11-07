#pragma once

struct DOS_Header
{
	unsigned short magicbytes;
	unsigned short partPag;
	unsigned short pageCnt;
	unsigned short reloCnt;
	unsigned short hdrSize;
	unsigned short minMem;
	unsigned short maxMem;
	unsigned short reloSS;
	unsigned short exeSP;
	unsigned short chksum;
	unsigned short exeIP;
	unsigned short reloCS;
	unsigned short tablOff;
	unsigned short overlay;
	unsigned short oemid;                     // OEM identifier (for e_oeminfo)
        unsigned short oeminfo;                   // OEM information; e_oemid specific
	unsigned char  res2[28];                  // Reserved words
	unsigned long offsetToPE;
};
typedef struct DOS_Header DOSHeader;

struct File_Header
{
    unsigned long   signature;
    unsigned short  Machine;
    unsigned short  NumberOfSections;
    unsigned long   TimeDateStamp;
    unsigned long   PointerToSymbolTable;
    unsigned long   NumberOfSymbols;
    unsigned short  SizeOfOptionalHeader;
    unsigned short  Characteristics;
};
typedef struct File_Header FileHeader;

struct PE_OptHeader
{
	//
	// Standard Fields
	//
	unsigned short magic;
	unsigned char majorLinkerVersion;
	unsigned char minorLinkerVersion;
	unsigned long sizeOfCode;
	unsigned long sizeOfInitializedData;
	unsigned long sizeOfUninitializedData;
	unsigned long addressOfEntryPoint;
	unsigned long baseOfCode;
	//
	// NT additional fields
	//
	unsigned long long imageBase;
	unsigned long sectionAlignment;
	unsigned long fileAlignment;
	unsigned short majorOSVersion;
	unsigned short minorOSVersion;
	unsigned short majorImageVersion;
	unsigned short minorImageVersion;
	unsigned short majorSubsystemVersion;
	unsigned short minorSubsystemVersion;
	unsigned long Win32VersionValue;
	unsigned long sizeOfImage;
	unsigned long sizeOfHeaders;
	unsigned long checksum;
	unsigned short subsystem;
	unsigned short DLLCharacteristics;
	unsigned long long sizeOfStackReserve;
	unsigned long long sizeOfStackCommit;
	unsigned long long sizeOfHeapReserve;
	unsigned long long sizeOfHeapCommit;
	unsigned long loaderFlags;
	unsigned long numberOfRVAAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
typedef struct PE_OptHeader PEOptHeader;

struct Section_Header
{
	unsigned char sectionName[8];
	unsigned long virtualSize;
	unsigned long virtualAddress;
	unsigned long sizeOfRawData;
	unsigned long pointerToRawData;
	unsigned long pointerToRelocations;
	unsigned long pointerToLineNumbers;
	unsigned short numberOfRelocations;
	unsigned short numberOfLineNumbers;
	unsigned long characteristics;
};
typedef struct Section_Header SectionHeader;
