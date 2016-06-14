#include "StdAfx.h"
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "Fp_CommonFile.h"


struct PE_Header 
{
	unsigned long signature;
	unsigned short machine;
	unsigned short numSections;
	unsigned long timeDateStamp;
	unsigned long pointerToSymbolTable;
	unsigned long numOfSymbols;
	unsigned short sizeOfOptionHeader;
	unsigned short characteristics;
};

struct PE_ExtHeader
{
	unsigned short magic;
	unsigned char majorLinkerVersion;
	unsigned char minorLinkerVersion;
	unsigned long sizeOfCode;
	unsigned long sizeOfInitializedData;
	unsigned long sizeOfUninitializedData;
	unsigned long addressOfEntryPoint;
	unsigned long baseOfCode;
	unsigned long baseOfData;
	unsigned long imageBase;
	unsigned long sectionAlignment;
	unsigned long fileAlignment;
	unsigned short majorOSVersion;
	unsigned short minorOSVersion;
	unsigned short majorImageVersion;
	unsigned short minorImageVersion;
	unsigned short majorSubsystemVersion;
	unsigned short minorSubsystemVersion;
	unsigned long reserved1;
	unsigned long sizeOfImage;
	unsigned long sizeOfHeaders;
	unsigned long checksum;
	unsigned short subsystem;
	unsigned short DLLCharacteristics;
	unsigned long sizeOfStackReserve;
	unsigned long sizeOfStackCommit;
	unsigned long sizeOfHeapReserve;
	unsigned long sizeOfHeapCommit;
	unsigned long loaderFlags;
	unsigned long numberOfRVAAndSizes;
	unsigned long exportTableAddress;
	unsigned long exportTableSize;
	unsigned long importTableAddress;
	unsigned long importTableSize;
	unsigned long resourceTableAddress;
	unsigned long resourceTableSize;
	unsigned long exceptionTableAddress;
	unsigned long exceptionTableSize;
	unsigned long certFilePointer;
	unsigned long certTableSize;
	unsigned long relocationTableAddress;
	unsigned long relocationTableSize;
	unsigned long debugDataAddress;
	unsigned long debugDataSize;
	unsigned long archDataAddress;
	unsigned long archDataSize;
	unsigned long globalPtrAddress;
	unsigned long globalPtrSize;
	unsigned long TLSTableAddress;
	unsigned long TLSTableSize;
	unsigned long loadConfigTableAddress;
	unsigned long loadConfigTableSize;
	unsigned long boundImportTableAddress;
	unsigned long boundImportTableSize;
	unsigned long importAddressTableAddress;
	unsigned long importAddressTableSize;
	unsigned long delayImportDescAddress;
	unsigned long delayImportDescSize;
	unsigned long COMHeaderAddress;
	unsigned long COMHeaderSize;
	unsigned long reserved2;
	unsigned long reserved3;
};


struct SectionHeader
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

struct MZHeader
{
	unsigned short signature;
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
	unsigned char reserved[32];
	unsigned long offsetToPE;
};


struct ImportDirEntry
{
	DWORD importLookupTable;
	DWORD timeDateStamp;
	DWORD fowarderChain;
	DWORD nameRVA;
	DWORD importAddressTable;
};



//******************************************************************************************
//
// This function reads the MZ, PE, PE extended and Section Headers from an EXE file.
//
//******************************************************************************************
 
bool readPEInfo(FILE *fp, MZHeader *outMZ, PE_Header *outPE, PE_ExtHeader *outpeXH,
				SectionHeader **outSecHdr)
{
	fseek(fp, 0, SEEK_END);
	long fileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
 
	if(fileSize < sizeof(MZHeader))
	{
		printf("File size too small\n");		
		return false;
	}
 
	// read MZ Header
	MZHeader mzH;
	fread(&mzH, sizeof(MZHeader), 1, fp);
 
	if(mzH.signature != 0x5a4d)		// MZ
	{
		printf("File does not have MZ header\n");
		return false;
	}
 
	//printf("Offset to PE Header = %X\n", mzH.offsetToPE);
 
	if((unsigned long)fileSize < mzH.offsetToPE + sizeof(PE_Header))
	{
		printf("File size too small\n");		
		return false;
	}
 
	// read PE Header
	fseek(fp, mzH.offsetToPE, SEEK_SET);
	PE_Header peH;
	fread(&peH, sizeof(PE_Header), 1, fp);
 
	//printf("Size of option header = %d\n", peH.sizeOfOptionHeader);
	//printf("Number of sections = %d\n", peH.numSections);
 
	if(peH.sizeOfOptionHeader != sizeof(PE_ExtHeader))
	{
		printf("Unexpected option header size.\n");
 
		return false;
	}
 
	// read PE Ext Header
	PE_ExtHeader peXH;
 
	fread(&peXH, sizeof(PE_ExtHeader), 1, fp);
 
	//printf("Import table address = %X\n", peXH.importTableAddress);
	//printf("Import table size = %X\n", peXH.importTableSize);
	//printf("Import address table address = %X\n", peXH.importAddressTableAddress);
	//printf("Import address table size = %X\n", peXH.importAddressTableSize);
 
 
	// read the sections
	SectionHeader *secHdr = new SectionHeader[peH.numSections];
 
	fread(secHdr, sizeof(SectionHeader) * peH.numSections, 1, fp);
 
	*outMZ = mzH;
	*outPE = peH;
	*outpeXH = peXH;
	*outSecHdr = secHdr;
 
	return true;
}
 
 
//******************************************************************************************
//
// This function calculates the size required to load an EXE into memory with proper alignment.
//
//******************************************************************************************
 
int calcTotalImageSize(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
				       SectionHeader *inSecHdr)
{
	int result = 0;
	int alignment = inpeXH->sectionAlignment;
 
	if(inpeXH->sizeOfHeaders % alignment == 0)
		result += inpeXH->sizeOfHeaders;
	else
	{
		int val = inpeXH->sizeOfHeaders / alignment;
		val++;
		result += (val * alignment);
	}
 
 
	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].virtualSize)
		{
			if(inSecHdr[i].virtualSize % alignment == 0)
				result += inSecHdr[i].virtualSize;
			else
			{
				int val = inSecHdr[i].virtualSize / alignment;
				val++;
				result += (val * alignment);
			}
		}
	}
 
	return result;
}
 

DWORD getImageSize()
{
	int imageSize = 0;
	char path[MAX_PATH] = {0};
	GetModuleFileNameA(NULL, path, MAX_PATH);
	FILE *fp = fopen(path, "rb");
	if(fp)
	{
		MZHeader mzH;
		PE_Header peH;
		PE_ExtHeader peXH;
		SectionHeader *secHdr;

		if(readPEInfo(fp, &mzH, &peH, &peXH, &secHdr))
		{
			imageSize = calcTotalImageSize(&mzH, &peH, &peXH, secHdr);
		}
		fclose(fp);
	}
	return imageSize;
}

void myprint( LPTSTR lpszDsp, int num )
{
	TCHAR szPath[MAX_PATH] = {0};
	
	swprintf(szPath, L"%s:0x%x\n", lpszDsp, num);
	OutputDebugString(szPath);
}

bool isOS64Bytes()
{
	SYSTEM_INFO si; 
	GetNativeSystemInfo(&si); 
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||    
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ) 
	{ 
		return true;
	} 
	else 
	{ 
		return false;
	}
}