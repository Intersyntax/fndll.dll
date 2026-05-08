#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef NTSTATUS (NTAPI* pRtlGetVersion) (PRTL_OSVERSIONINFOW);

static HMODULE hNtDll=NULL;

typedef struct
{
	char name[256];
	DWORD ssn;
} SyscallEntry;

SyscallEntry* entries=NULL;
int entryCount,entryCapacity=0;

void AddEntry(LPCCH name,DWORD ssn)
{
	if (entryCount >= entryCapacity)
	{
		entryCapacity=(entryCapacity==0)?0x100:entryCapacity*2;
		entries=(SyscallEntry*)realloc(entries,entryCapacity*sizeof(SyscallEntry));
		if (!entries)
		{
			printf("realloc failed\n");
			__fastfail(3u);
		}
	}
	strcpy_s(entries[entryCount].name,sizeof(entries[entryCount].name),name);
	entries[entryCount].ssn=ssn;
	++entryCount;
}

void Extract()
{
	PBYTE base=(PBYTE)hNtDll;
	PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(base+dos->e_lfanew);

	DWORD exportRva=nt->OptionalHeader.DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exportDir=(PIMAGE_EXPORT_DIRECTORY)(base+exportRva);

	PDWORD names=(PDWORD)(base+exportDir->AddressOfNames);
	PDWORD funcs=(PDWORD)(base+exportDir->AddressOfFunctions);
	PWORD ordinals=(PWORD)(base+exportDir->AddressOfNameOrdinals);
	printf("Scanning %lu exported functions...\n",exportDir->NumberOfNames);

	for(DWORD i=0;i<exportDir->NumberOfNames;++i)
	{
		PCHAR name=(PCHAR)(base+names[i]);
		PBYTE funcAddr=base+funcs[ordinals[i]];

		if (funcAddr[0]==0x4C && funcAddr[1]==0x8B &&
			funcAddr[2]==0xD1 && funcAddr[3]==0xB8)
		{
			DWORD ssn=*(PDWORD)(funcAddr+4);
			AddEntry(name,ssn);
			printf("Found: %-50s SSN: 0x%04X (%d)\n",name,ssn,(int)ssn);
		}
	}
}

void lower(char dst[],LPCCH src[],size_t dst_size)
{
	strncpy_s(dst,dst_size,src,_TRUNCATE);
	for(char*p=dst;*p&&p<dst+dst_size-1;++p)*p=tolower(*p);
}

int RtlGetVersion(RTL_OSVERSIONINFOW* osvi)
{
	pRtlGetVersion rgv=(pRtlGetVersion)GetProcAddress(hNtDll,"RtlGetVersion");
	return (rgv(osvi)==0)?0:1;
}

void GenerateNASM(LPCCH filename)
{
	FILE* f=fopen(filename,"w");
	if (!f)
	{
		printf("Failed to create %s",filename);
		return;
	}

	RTL_OSVERSIONINFOW osvi={0};
	osvi.dwOSVersionInfoSize=sizeof(osvi);
	if(RtlGetVersion(&osvi) == 0)
		fprintf(f,"; Stubs Generated For Windows %u.%u.%u\n",
			osvi.dwMajorVersion,
			osvi.dwMinorVersion,
			osvi.dwBuildNumber);
	fprintf(f,"; Total Syscalls: %d\n\n",entryCount);
	fprintf(f,"section .text\nBITS 64\n\n");
	for (int i=0;i<entryCount;++i)
	{
		//printf("inside you\n");
		char l[256];
		lower(l,entries[i].name,sizeof(l));

		fprintf(f,"; https://ntdoc.m417z.com/%s\n",l);
		fprintf(f,"global %s\n%s:\n",entries[i].name,entries[i].name);
		fprintf(f,"   mov r10, rcx\n");
		fprintf(f,"   mov eax, 0%dh\n",entries[i].ssn);
		fprintf(f,"   syscall\n   ret\n\n");
	}
	fclose(f);
}

void GenerateMASM(LPCCH filename)
{
	FILE* f=fopen(filename,"w");
	if (!f)
	{
		printf("Failed to create %s",filename);
		return;
	}

	RTL_OSVERSIONINFOW osvi={0};
	osvi.dwOSVersionInfoSize=sizeof(osvi);
	if(RtlGetVersion(&osvi) == 0)
		fprintf(f,"; Stubs Generated For Windows %u.%u.%u\n",
			osvi.dwMajorVersion,
			osvi.dwMinorVersion,
			osvi.dwBuildNumber);
	fprintf(f,"; Total Syscalls: %d\n\n",entryCount);
	fprintf(f,".CODE\n\n");
	for (int i=0;i<entryCount;++i)
	{
		//printf("inside you\n");
		char l[256];
		lower(l,entries[i].name,sizeof(l));

		fprintf(f,"; https://ntdoc.m417z.com/%s\n",l);
		fprintf(f,"%s PROC\n",entries[i].name);
		fprintf(f,"   mov r10, rcx\n");
		fprintf(f,"   mov eax, %dh\n",entries[i].ssn);
		fprintf(f,"   syscall\n   ret\n");
		fprintf(f,"%s ENDP\n\n",entries[i].name);
	}
	fprintf(f,"END\n");
	fclose(f);
}

int usage(char* arg)
{
	printf("Usage:\n   %s masm\n   %s nasm",arg,arg);
	return 1;
}

int main(int argc, char* argv[])
{
	unsigned char masm=0;

	if (argc<2)
	{
		printf("No mode specified\n");
		return usage(argv[0]);
	}
	else if (argc>2)
	{
		printf("Too many arguments passed\n");
		return usage(argv[0]);
	}

	char l[16];
	lower(l,argv[1],sizeof(l));

	if (stricmp(l,"masm")==0)
		masm=1;
	else if (stricmp(l,"nasm")==0)
	{
		// good
	}
	else
	{
		printf("Unknown mode chosen\n");
		return usage(argv[0]);
	}


	printf("Hi\n");
	hNtDll=GetModuleHandleA("ntdll.dll");
	printf("ntdll.dll at: 0x%p\n\n",hNtDll);
	Extract();
	printf("\nTotal functions with syscall insns: %d\n",entryCount);
	if (entryCount > 0)
	{
		if (masm)
		{
			printf("Mode: MASM\n");
			GenerateMASM("m-fndll.asm");
			printf("\nGenerated: m-fndll.asm\n");
			printf("Compiling...\n");
			int result = system("ml64 /c /Fo fndll.obj m-fndll.asm");
			if (result == 0)
				printf("Success!\n");
			else
				printf("Compilation failed\n");
		}
		else // nasm
		{
			printf("Mode: NASM\n");
			GenerateNASM("n-fndll.asm");
			printf("\nGenerated: n-fndll.asm\n");
			printf("Compiling...\n");
			int result = system("nasm -f win64 -o fndll.obj n-fndll.asm");
			if (result == 0)
				printf("Success!\n");
			else
				printf("Compilation failed\n");
		}
	}
	free(entries);
	return 0;
}
