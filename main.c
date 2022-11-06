#include <stdio.h>
#include <windows.h>
#include <time.h>
#include "PEheader.h"

// Parse the PE file to get the PE structure
BOOL parsePEInfo(FILE *fp)
{
	DOSHeader dosH;
	long fileSize;
	FileHeader fileH;
	PEOptHeader optionalH;
	SectionHeader *secHdr;
	struct tm  ts;
	char       buf[80];

	fseek(fp, 0, SEEK_END);
	fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (fileSize < sizeof(DOSHeader))
	{
		printf("[-] File size too small\n");
		return FALSE;
	}

	// read MZ Header
	fread(&dosH, sizeof(DOSHeader), 1, fp);

	if (dosH.magicbytes != 0x5a4d)      // MZ
	{
		printf("[-] File does not have MZ header\n");
		return FALSE;
	}

	printf("[+] Offset to PE Header = %lX\n", dosH.offsetToPE);

	if ((unsigned long)fileSize < dosH.offsetToPE + sizeof(FileHeader))
	{
		printf("[-] File size too small\n");
		return FALSE;
	}

	// read PE Header
	fseek(fp, dosH.offsetToPE, SEEK_SET);
	fread(&fileH, sizeof(FileHeader), 1, fp);

	printf("[+] Size of Optional header = %d\n", fileH.SizeOfOptionalHeader);
	printf("[+] Number of sections = %d\n", fileH.NumberOfSections);
	ts = *localtime((time_t*)&fileH.TimeDateStamp);
	strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
	printf("[+] Time Date Stamp = %ld  %s\n", fileH.TimeDateStamp, buf);

	if (fileH.SizeOfOptionalHeader != sizeof(PEOptHeader))
	{
		printf("[-] Optional header size missmatch.\n");

		return FALSE;
	}

	// read PE Ext Header
	fread(&optionalH, sizeof(PEOptHeader), 1, fp);

	printf("\n******* Optional Header *******\n");
	printf("\tMagic %02X\n",optionalH.magic);
	printf("\tLinker Ver. (Major) %02X\n",optionalH.majorLinkerVersion);
	printf("\tLinker Ver. (Minor) %02X\n",optionalH.minorLinkerVersion);
	printf("\tSize of Code %lX\n",optionalH.sizeOfCode);
	printf("\tSize of Initialized Data %lX\n",optionalH.sizeOfInitializedData);
	printf("\tSize of Uninitialized Data %lX\n",optionalH.sizeOfUninitializedData);
	printf("\tEntry Point %lX\n",optionalH.addressOfEntryPoint);
	printf("\tBase of Code %lX\n",optionalH.baseOfCode);
	printf("\tImage Base %llX\n",optionalH.imageBase);
	printf("\tSection Alignment %lX\n",optionalH.sectionAlignment);
	printf("\tFile Alignment %lX\n",optionalH.fileAlignment);
	printf("\tOS Ver. (Major) %u\n",optionalH.majorOSVersion);
	printf("\tOS Ver. (Minor) %u\n",optionalH.minorOSVersion);
	printf("\tSubsystem Ver. (Major) %u\n",optionalH.majorSubsystemVersion);
	printf("\tSubsystem Ver. (Minor) %u\n",optionalH.minorSubsystemVersion);
	printf("\tSize of Image %lX\n",optionalH.sizeOfImage);
	printf("\tSize of Headers %lX\n",optionalH.sizeOfHeaders);
	printf("\tChecksum %lX\n",optionalH.checksum);
	printf("\tSubsystem %u\n",optionalH.subsystem);

	printf("\n******* DATA DIRECTORY *******\n");
	printf("\tExport Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[2].VirtualAddress, optionalH.DataDirectory[2].Size);
	printf("\tImport Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[3].VirtualAddress, optionalH.DataDirectory[3].Size);
	printf("\tResource Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[4].VirtualAddress, optionalH.DataDirectory[4].Size);
	printf("\tException Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[5].VirtualAddress, optionalH.DataDirectory[5].Size);
	printf("\tSecurity Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[6].VirtualAddress, optionalH.DataDirectory[6].Size);
	printf("\tBase Relocation Table Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[7].VirtualAddress, optionalH.DataDirectory[7].Size);
	printf("\tDebug Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[8].VirtualAddress, optionalH.DataDirectory[8].Size);
	printf("\tArchitecture Specific Data Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[9].VirtualAddress, optionalH.DataDirectory[9].Size);
	printf("\tRVA Of GlobalPtr Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[10].VirtualAddress, optionalH.DataDirectory[10].Size);
	printf("\tTLS Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[11].VirtualAddress, optionalH.DataDirectory[11].Size);
	printf("\tLoad Configuration Directory Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[12].VirtualAddress, optionalH.DataDirectory[12].Size);
	printf("\tBound Import Directory in headers Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[13].VirtualAddress, optionalH.DataDirectory[13].Size);
	printf("\tImport Address Table Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[14].VirtualAddress, optionalH.DataDirectory[14].Size);
	printf("\tDelay Load Import Descriptors Address: 0x%lx; Size: 0x%lx\n", optionalH.DataDirectory[15].VirtualAddress, optionalH.DataDirectory[15].Size);

	// read the sections
	secHdr = (SectionHeader*)malloc(sizeof(SectionHeader)* (fileH.NumberOfSections));

	fread(secHdr, sizeof(SectionHeader) * fileH.NumberOfSections, 1, fp);

	printf("\n******* SECTION HEADERS *******\n");
	for (int i = 0; i < fileH.NumberOfSections; i++)
	{
		printf("\t%s\n", secHdr->sectionName);
		printf("\t\t0x%lx\t\tVirtual Size\n", secHdr->virtualSize);
		printf("\t\t0x%lx\t\tVirtual Address\n", secHdr->virtualAddress);
		printf("\t\t0x%lx\t\tSize Of Raw Data\n", secHdr->sizeOfRawData);
		printf("\t\t0x%lx\t\tPointer To Raw Data\n", secHdr->pointerToRawData);
		printf("\t\t0x%lx\t\tPointer To Relocations\n", secHdr->pointerToRelocations);
		printf("\t\t0x%lx\t\tPointer To Line Numbers\n", secHdr->pointerToLineNumbers);
		printf("\t\t0x%x\t\tNumber Of Relocations\n", secHdr->numberOfRelocations);
		printf("\t\t0x%x\t\tNumber Of Line Numbers\n", secHdr->numberOfLineNumbers);
		printf("\t\t0x%lx\tCharacteristics\n", secHdr->characteristics);
		secHdr++;
	}

	return TRUE;
}

int main(int argc, char *argv[])
{
	FILE *fp;

	if (argc < 2 || argc > 2)
	{
		printf("\nUsage: %s [filename]\n", argv[0]);
		return 1;
	}

	if (argc == 2) 
	{
		fopen_s(&fp, argv[1], "rb");
		if (fp)
		{
			if (parsePEInfo(fp)) // Parse PE structure
			{
				printf("[+] Parsing Completed!\n");
			}
			else
			{
				printf("[-] Parsing Failed!\n");
				fclose(fp);
				return 1;
			}

			fclose(fp);
		}
		else
			printf("\n[-] Cannot open the EXE file!\n");
	}

	return 0;
}