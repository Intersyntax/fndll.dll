#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
	char name[256];
	DWORD ssn;
} SyscallEntry;

SyscallEntry* entries=NULL;
int entryCount,entryCapacity=0;

void AddEntry(LPCCH name, DWORD ssn)
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

void Extract(HMODULE hNtDll)
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

void Generate(LPCCH filename)
{
	FILE* f=fopen(filename,"w");
	if (!f)
	{
		printf("Failed to create %s",filename);
		return;
	}

	fprintf(f,"; Total Syscalls: %d\n\n",entryCount);
	fprintf(f,".CODE\n\n");
	for (int i=0;i<entryCount;++i)
	{
		char* l=entries[i].name;
		for(char *p=l;*p;p++)*p=tolower(*p);
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

int main()
{
	printf("Hi\n");
	HMODULE hNtDll=GetModuleHandleA("ntdll.dll");
	printf("ntdll.dll at: 0x%p\n\n",hNtDll);
	Extract(hNtDll);
	printf("\nTotal functions with syscall insns: %d\n",entryCount);
	if (entryCount > 0)
	{
		Generate("fndll.asm");
		printf("\nGenerated: fndll.asm\n");

		printf("Compiling with MASM...\n");
		int result=system("ml64.exe /c /Fo fndll.obj fndll.asm");
		if (result==0)
			printf("Success!\n");
		else
			printf("Compilation failed\n");
	}
	free(entries);
	return 0;
}
