#pragma once




FORCEINLINE PLARGE_INTEGER BaseFormatTimeOut(OUT PLARGE_INTEGER Timeout, IN ULONG dwMilliseconds)
{
	if (dwMilliseconds == INFINITE)
	{
		Timeout->HighPart = 0x80000000;
		Timeout->LowPart = 0;
	}
	else Timeout->QuadPart = dwMilliseconds * -10000LL;
	return Timeout;
}

FORCEINLINE VOID NTAPI RtlInitUnicodeString(IN PUNICODE_STRING DestinationString, IN PCWSTR SourceString)
{
	USHORT MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL), Size = 0;

	if (SourceString)
	{
		do ++Size;
		while (SourceString[Size]);

		Size = Size * sizeof(WCHAR);

		if (Size > MaxSize)
			Size = MaxSize;

		DestinationString->Length = (USHORT)Size;
		DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}
FORCEINLINE VOID NTAPI RtlInitAnsiString(IN PANSI_STRING DestinationString, IN PCSTR SourceString)
{
	SIZE_T Size;

	if (SourceString)
	{
		Size = strlen(SourceString);
		if (Size > (MAXUSHORT - sizeof(CHAR))) Size = MAXUSHORT - sizeof(CHAR);
		DestinationString->Length = (USHORT)Size;
		DestinationString->MaximumLength = (USHORT)Size + sizeof(CHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PCHAR)SourceString;
}






FORCEINLINE PVOID GetModuleBase(PPEB Peb, PCWSTR ModuleName)
{
	PVOID ImageBase = NULL;
	if (Peb)
	{
		if (ModuleName)
		{
			for (PLIST_ENTRY ListEntry = Peb->Ldr->InInitializationOrderModuleList.Flink; ListEntry != &Peb->Ldr->InInitializationOrderModuleList; ListEntry = ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
				if (wstrcmp(LdrEntry->BaseDllName.Buffer, ModuleName) == 0)
				{
					ImageBase = LdrEntry->DllBase;
					break;
				}
			}
		}
		else ImageBase = Peb->ImageBaseAddress;
	}
	return ImageBase;
}
FORCEINLINE PVOID GetProcedureAddress(PVOID ImageBase, PCSTR ImportName)
{
	PVOID ProcedureAddress = NULL;
	if (ImageBase)
	{
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)ImageBase;
		if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + pIDH->e_lfanew);
			if (pINH->Signature == IMAGE_NT_SIGNATURE)
			{
				PIMAGE_DATA_DIRECTORY pIDD = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				if (pIDD->VirtualAddress && pIDD->Size)
				{
					PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageBase + pIDD->VirtualAddress);

					PULONG Names = (PULONG)((PUCHAR)ImageBase + pIED->AddressOfNames);
					PULONG Functions = (PULONG)((PUCHAR)ImageBase + pIED->AddressOfFunctions);
					PUSHORT NameOrdinals = (PUSHORT)((PUCHAR)ImageBase + pIED->AddressOfNameOrdinals);

					if ((ULONG_PTR)ImportName <= 0xFFFF)
					{
						ProcedureAddress = (PUCHAR)ImageBase + Functions[(ULONG_PTR)ImportName];
					}
					else
					{
						for (ULONG i = 0; i < pIED->NumberOfNames; i++)
						{
							if (strcmp((PCHAR)ImageBase + Names[i], ImportName) == 0)
							{
								ProcedureAddress = (PUCHAR)ImageBase + Functions[NameOrdinals[i]];
								break;
							}
						}
					}
				}
			}
		}
	}
	return ProcedureAddress;
}
FORCEINLINE PVOID GetFunctionAddress(PPEB Peb, PCWSTR ModuleName, PCSTR FunctionName)
{
	PVOID ImageBase = GetModuleBase(Peb, ModuleName);
	return ImageBase ? GetProcedureAddress(ImageBase, FunctionName) : NULL;
}


namespace kernel32
{
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

	FORCEINLINE NTSTATUS CreateThread(OUT PHANDLE ThreadHandle, IN HANDLE ProcessHandle, IN ULONG DesiredAccess, IN PVOID StartAddress, IN PVOID Parameter,
		IN ULONG CreateFlags = THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, IN ULONG_PTR StackSize = 0x1000, IN ULONG_PTR MaximumStackSize = 0x1000)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);

		return NtCreateThreadEx(ThreadHandle, DesiredAccess, &ObjectAttributes, ProcessHandle, StartAddress, Parameter, CreateFlags, NULL, StackSize, MaximumStackSize, NULL);
	}


	FORCEINLINE PVOID VirtualAllocEx(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN ULONG_PTR RegionSize, IN ULONG AllocationType, IN ULONG Protect)
	{
		return (NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, NULL, &RegionSize, AllocationType, Protect) == STATUS_SUCCESS) ? BaseAddress : NULL;
	}
	FORCEINLINE BOOLEAN VirtualProtectEx(HANDLE ProcessHandle, PVOID BaseAddress, ULONG_PTR RegionSize, ULONG NewProtect, PULONG OldProtect)
	{
		return NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &RegionSize, NewProtect, OldProtect) == STATUS_SUCCESS;
	}

	FORCEINLINE VOID Sleep(ULONG dwMilliseconds)
	{
		LARGE_INTEGER Time;
		NtDelayExecution(FALSE, BaseFormatTimeOut(&Time, dwMilliseconds));
	}
	FORCEINLINE NTSTATUS NTAPI SetPrivilege(IN ULONG Privilege, IN ULONG Attributes)
	{
		TOKEN_PRIVILEGES Privileges;
		Privileges.PrivilegeCount = 1;
		Privileges.Privileges[0].Attributes = Attributes;
		Privileges.Privileges[0].Luid.LowPart = Privilege;
		Privileges.Privileges[0].Luid.HighPart = 0;

		HANDLE Token;
		NTSTATUS status = NtOpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &Token);
		if (status == STATUS_NO_TOKEN)
		{
			status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token);
		}
		if (status == STATUS_SUCCESS)
		{
			status = NtAdjustPrivilegesToken(Token, FALSE, &Privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
			NtClose(Token);
		}
		return status;
	}
	FORCEINLINE NTSTATUS CreateFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
	{
		UNICODE_STRING UnicodeObjectName;
		RtlInitUnicodeString(&UnicodeObjectName, filename);

		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		IO_STATUS_BLOCK IoStatusBlock;
		return NtCreateFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock, NULL, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
	FORCEINLINE NTSTATUS OpenFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG ShareAccess, ULONG OpenOptions)
	{
		UNICODE_STRING UnicodeObjectName;
		RtlInitUnicodeString(&UnicodeObjectName, filename);

		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		IO_STATUS_BLOCK IoStatusBlock;
		return NtOpenFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock, ShareAccess, OpenOptions);
	}
	FORCEINLINE NTSTATUS WriteFile(HANDLE FileHandle, PVOID Buffer, ULONG_PTR Offset, ULONG_PTR Length, PULONG_PTR pWritted)
	{
		LARGE_INTEGER BytesOffset;
		BytesOffset.QuadPart = Offset;

		IO_STATUS_BLOCK IoStatusBlock;
		NTSTATUS status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, (ULONG)Length, &BytesOffset, NULL);
		if (status == STATUS_PENDING)
		{
			status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
			if (NT_SUCCESS(status)) status = IoStatusBlock.Status;
		}
		if (NT_SUCCESS(status))
		{
			if (pWritted)
				*pWritted = IoStatusBlock.Information;
		}
		return status;
	}
	FORCEINLINE NTSTATUS DeleteFileEx(IN HANDLE FileHandle)
	{
		BOOLEAN DeleteFile = TRUE;

		IO_STATUS_BLOCK IoStatusBlock;
		return NtSetInformationFile(FileHandle, &IoStatusBlock, &DeleteFile, sizeof(DeleteFile), FileDispositionInformation);
	}
	FORCEINLINE NTSTATUS DeleteFile(IN PCWSTR FilePath, IN BOOLEAN Close = TRUE)
	{
		/*
		STATUS_OBJECT_NAME_NOT_FOUND - файл отсутствует
		STATUS_SHARING_VIOLATION - Сайл используетс§
		*/
		HANDLE FileHandle = NULL;
		NTSTATUS status = OpenFile(&FileHandle, FilePath, FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL);
		if (status == STATUS_SUCCESS)
		{
			status = DeleteFileEx(FileHandle);
			if (Close == TRUE)
			{
				NtClose(FileHandle);
			}
		}
		if (status == STATUS_OBJECT_NAME_NOT_FOUND)
			status = STATUS_SUCCESS;

		return status;
	}

	FORCEINLINE NTSTATUS MoveFileEx(IN HANDLE FileHandle, IN PCWSTR NewFileName, IN BOOLEAN ReplaceIfExists)
	{
		FILE_RENAME_INFORMATION Information;

		Information.ReplaceIfExists = ReplaceIfExists;
		Information.RootDirectory = NULL;

		Information.FileNameLength = ULONG(wcslen(NewFileName) * 2);
		__movsw((unsigned short*)Information.FileName, (unsigned short*)NewFileName, Information.FileNameLength);

		IO_STATUS_BLOCK IoStatusBlock;
		return NtSetInformationFile(FileHandle, &IoStatusBlock, &Information, sizeof(Information), FileRenameInformation);
	}
	FORCEINLINE NTSTATUS MoveFile(IN PCWSTR ExistingFileName, IN PCWSTR NewFileName, IN BOOLEAN ReplaceIfExists)
	{
		HANDLE FileHandle = NULL;
		NTSTATUS status = OpenFile(&FileHandle, ExistingFileName, FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL);
		if (status == STATUS_SUCCESS)
		{
			status = MoveFileEx(FileHandle, NewFileName, ReplaceIfExists);
			NtClose(FileHandle);
		}
		return status;
	}

	FORCEINLINE NTSTATUS SetFileAttributes(IN HANDLE FileHandle, IN ULONG FileAttributes)
	{
		FILE_BASIC_INFORMATION FileBasicInfo;
		FileBasicInfo.FileAttributes = FileAttributes;

		IO_STATUS_BLOCK IoStatusBlock;
		return NtSetInformationFile(FileHandle, &IoStatusBlock, &FileBasicInfo, sizeof(FileBasicInfo), FileBasicInformation);
	}
	FORCEINLINE NTSTATUS OpenProcess(OUT PHANDLE ProcessHandle, IN ULONG DesiredAccess, IN BOOLEAN InheritHandle, IN HANDLE UniqueProcessId)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, DesiredAccess ? OBJ_INHERIT : NULL, NULL, NULL);

		CLIENT_ID ClientId;
		ClientId.UniqueProcess = UniqueProcessId;
		ClientId.UniqueThread = NULL;

		return NtOpenProcess(ProcessHandle, DesiredAccess, &ObjectAttributes, &ClientId);
	}
	FORCEINLINE NTSTATUS OpenThread(OUT PHANDLE ThreadHandle, IN ULONG DesiredAccess, IN BOOLEAN InheritHandle, IN HANDLE UniqueThreadId)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, DesiredAccess ? OBJ_INHERIT : NULL, NULL, NULL);

		CLIENT_ID ClientId;
		ClientId.UniqueProcess = NULL;
		ClientId.UniqueThread = UniqueThreadId;

		return NtOpenThread(ThreadHandle, DesiredAccess, &ObjectAttributes, &ClientId);
	}


	FORCEINLINE NTSTATUS DeviceIoControl(IN HANDLE Device, IN ULONG IoControlCode, IN OPTIONAL PVOID InBuffer, IN ULONG InBufferSize, OUT OPTIONAL PVOID OutBuffer, IN ULONG OutBufferSize, OUT OPTIONAL PULONG BytesReturned, IN OUT OPTIONAL LPOVERLAPPED Overlapped)
	{
		NTSTATUS status = STATUS_SUCCESS;
		if (Overlapped)
		{
			Overlapped->Internal = STATUS_PENDING;
			PVOID ApcContext = (((ULONG_PTR)Overlapped->hEvent & 0x1) ? NULL : Overlapped);

			if (((IoControlCode >> 16) == FILE_DEVICE_FILE_SYSTEM))
			{
				status = NtFsControlFile(Device, Overlapped->hEvent, NULL, ApcContext, (PIO_STATUS_BLOCK)Overlapped, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
			}
			else
			{
				status = NtDeviceIoControlFile(Device, Overlapped->hEvent, NULL, ApcContext, (PIO_STATUS_BLOCK)Overlapped, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
			}
			if (BytesReturned)
			{
				*BytesReturned = (ULONG)Overlapped->InternalHigh;
			}
		}
		else
		{
			IO_STATUS_BLOCK IoStatusBlock;
			if (((IoControlCode >> 16) == FILE_DEVICE_FILE_SYSTEM))
			{
				status = NtFsControlFile(Device, NULL, NULL, NULL, &IoStatusBlock, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
			}
			else
			{
				status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &IoStatusBlock, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
			}
			if (status == STATUS_PENDING)
			{
				status = NtWaitForSingleObject(Device, FALSE, NULL);
				if (NT_SUCCESS(status)) status = IoStatusBlock.Status;
			}
			if (BytesReturned)
			{
				*BytesReturned = (ULONG)IoStatusBlock.Information;
			}
		}
		return status;
	}

	FORCEINLINE NTSTATUS CreateFileFromMemory(IN PCWSTR FilePath, IN PVOID Buffer, IN ULONG_PTR Length, IN ULONG FileAttributes)
	{
		HANDLE FileHandle;
		NTSTATUS status = CreateFile(&FileHandle, FilePath, GENERIC_ALL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, FILE_CREATE, NULL, NULL);
		if (NT_SUCCESS(status))
		{
			if (FileAttributes)
				SetFileAttributes(FileHandle, FileAttributes);

			status = WriteFile(FileHandle, Buffer, NULL, Length, NULL);

			NtClose(FileHandle);
		}
		return status;
	}

	FORCEINLINE NTSTATUS OpenKey(OUT PHANDLE KeyHandle, HANDLE RootKeyHandle, IN ACCESS_MASK DesiredAccess, IN PCWSTR Key, IN ULONG OpenOptions)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		UNICODE_STRING UnicodeKey;

		RtlInitUnicodeString(&UnicodeKey, Key);
		InitializeObjectAttributes(&ObjectAttributes, &UnicodeKey, OBJ_CASE_INSENSITIVE, RootKeyHandle, NULL);

		return NtOpenKeyEx(KeyHandle, MAXIMUM_ALLOWED, &ObjectAttributes, NULL);
	}
	FORCEINLINE NTSTATUS CreateKey(OUT PHANDLE KeyHandle, IN HANDLE RootKeyHandle, IN ULONG Desired, IN PCWSTR SubKey, IN PCWSTR Class, IN ULONG Options, OUT OPTIONAL PULONG Disposition)
	{
		UNICODE_STRING UnicodeObjectName;
		RtlInitUnicodeString(&UnicodeObjectName, SubKey);

		UNICODE_STRING UnicodeClass;
		RtlInitUnicodeString(&UnicodeClass, Class);

		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, RootKeyHandle, NULL);

		return NtCreateKey(KeyHandle, MAXIMUM_ALLOWED, &ObjectAttributes, NULL, &UnicodeClass, NULL, Disposition);
	}
	FORCEINLINE NTSTATUS SetValueKey(IN HANDLE KeyHandle, IN PCWSTR ValueName, IN OPTIONAL ULONG TitleIndex, IN ULONG Type, IN OPTIONAL PVOID Data, IN ULONG DataSize)
	{
		UNICODE_STRING UnicodeValueName;
		RtlInitUnicodeString(&UnicodeValueName, ValueName);

		return NtSetValueKey(KeyHandle, &UnicodeValueName, TitleIndex, Type, Data, DataSize);
	}

	FORCEINLINE NTSTATUS LoadDriver(IN PCWSTR DriverServiceName)
	{
		UNICODE_STRING UnicodeString;
		RtlInitUnicodeString(&UnicodeString, DriverServiceName);
		return NtLoadDriver(&UnicodeString);
	}
	FORCEINLINE NTSTATUS UnloadDriver(IN PCWSTR DriverServiceName)
	{
		UNICODE_STRING UnicodeString;
		RtlInitUnicodeString(&UnicodeString, DriverServiceName);
		return NtUnloadDriver(&UnicodeString);
	}

	FORCEINLINE NTSTATUS LoadUnloadDriver(IN PCWSTR DriverServiceName, IN OPTIONAL PCWSTR ImageFilePath, IN ULONG Type = 1, IN ULONG Start = 0xFFFFFFFF)
	{
		HANDLE Key;
		NTSTATUS status;
		if (ImageFilePath)
		{
			status = CreateKey(&Key, NULL, MAXIMUM_ALLOWED, DriverServiceName, NULL, NULL, NULL);
			if (NT_SUCCESS(status))
			{
				ULONG ImagePathLength = 0;
				do ++ImagePathLength;
				while (ImageFilePath[ImagePathLength]);

				WCHAR constexpr StrImagePath[] = L"ImagePath";
				WCHAR constexpr StrStart[] = L"Start";
				WCHAR constexpr StrType[] = L"Type";

				SetValueKey(Key, StrImagePath, NULL, REG_SZ, (PVOID)ImageFilePath, (ImagePathLength + 1) * sizeof(WCHAR));
				SetValueKey(Key, StrType, NULL, REG_DWORD, &Type, sizeof(Type));

				if (Start != 0xFFFFFFFF)
					SetValueKey(Key, StrStart, NULL, REG_DWORD, &Start, sizeof(Start));

				status = LoadDriver(DriverServiceName);
				if (NT_FAILED(status)) NtDeleteKey(Key);
				NtClose(Key);
			}
		}
		else
		{
			status = OpenKey(&Key, NULL, MAXIMUM_ALLOWED, DriverServiceName, NULL);
			if (NT_SUCCESS(status))
			{
				status = UnloadDriver(DriverServiceName);
				if (NT_SUCCESS(status)) NtDeleteKey(Key);
				NtClose(Key);
			}
		}

		return status;
	}

	FORCEINLINE PSYSTEM_HANDLE_INFORMATION GetSystemHandles()
	{
		PVOID Buffer = NULL;
		ULONG BufferLength = NULL;

		while (true)
		{
			NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, Buffer, BufferLength, &BufferLength);
			if (status == STATUS_SUCCESS) break;

			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (Buffer != NULL)
				{
					VirtualFree(Buffer, NULL, MEM_RELEASE);
				}
				Buffer = VirtualAlloc(NULL, BufferLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}
		}
		return (PSYSTEM_HANDLE_INFORMATION)Buffer;
	}
};