#pragma once
#ifndef FILE_DEVICE_BEEP
#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026
#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_FIPS                0x0000003A
#define FILE_DEVICE_INFINIBAND          0x0000003B
#define FILE_DEVICE_VMBUS               0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER      0x0000003F
#define FILE_DEVICE_WPD                 0x00000040
#define FILE_DEVICE_BLUETOOTH           0x00000041
#define FILE_DEVICE_MT_COMPOSITE        0x00000042
#define FILE_DEVICE_MT_TRANSPORT        0x00000043
#define FILE_DEVICE_BIOMETRIC           0x00000044
#define FILE_DEVICE_PMI                 0x00000045
#define FILE_DEVICE_EHSTOR              0x00000046
#define FILE_DEVICE_DEVAPI              0x00000047
#define FILE_DEVICE_GPIO                0x00000048
#define FILE_DEVICE_USBEX               0x00000049
#define FILE_DEVICE_CONSOLE             0x00000050
#define FILE_DEVICE_NFP                 0x00000051
#define FILE_DEVICE_SYSENV              0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK       0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE    0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION 0x00000055
#define FILE_DEVICE_TRUST_ENV           0x00000056
#define FILE_DEVICE_UCM                 0x00000057
#define FILE_DEVICE_UCMTCPCI            0x00000058
#define FILE_DEVICE_PERSISTENT_MEMORY   0x00000059
#define FILE_DEVICE_NVDIMM              0x0000005a
#define FILE_DEVICE_HOLOGRAPHIC         0x0000005b
#define FILE_DEVICE_SDFXHCI             0x0000005c
#define FILE_DEVICE_UCMUCSI             0x0000005d
#define FILE_DEVICE_PRM                 0x0000005e
#define FILE_DEVICE_EVENT_COLLECTOR     0x0000005f
#define FILE_DEVICE_USB4                0x00000060
#define FILE_DEVICE_SOUNDWIRE           0x00000061
#endif

#ifdef SetFileAttributes
#undef SetFileAttributes
#endif
#ifdef CreateFile
#undef CreateFile
#endif
#ifdef DeleteFile
#undef DeleteFile
#endif
#ifdef MoveFileEx
#undef MoveFileEx
#endif
#ifdef MoveFile
#undef MoveFile
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((LONG)(status) >= 0)
#endif
#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif
#ifndef NT_FAILED
#define NT_FAILED(status) ((LONG)(status) < 0)
#endif

#ifndef MAKELONG
#define MAKELONG(a, b)      ((ULONG)(((USHORT)(((ULONG)(a)) & 0xffff)) | ((ULONG)((USHORT)(((ULONG)(b)) & 0xffff))) << 16))
#endif
#ifndef MAKELONGLONG
#define MAKELONGLONG(l, h)	((ULONGLONG)(((ULONG)(l) & 0xffffffff) | (((ULONGLONG)(h) & 0xffffffff) << 32)))
#endif

#define MINCHAR     0x80        // winnt
#define MAXCHAR     0x7f        // winnt
#define MINSHORT    0x8000      // winnt
#define MAXSHORT    0x7fff      // winnt
#define MINLONG     0x80000000  // winnt
#define MAXLONG     0x7fffffff  // winnt
#define MAXUCHAR    0xff        // winnt
#define MAXUSHORT   0xffff      // winnt
#define MAXULONG    0xffffffff  // winnt

#ifndef DECLSPEC_NOINLINE
#define DECLSPEC_NOINLINE  __declspec(noinline)
#endif

#ifndef _NTDEF_
typedef LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005
#endif

#ifndef OBJ_INHERIT
#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L
#endif

#ifndef SE_MIN_WELL_KNOWN_PRIVILEGE
#define SE_MIN_WELL_KNOWN_PRIVILEGE         (2L)
#define SE_CREATE_TOKEN_PRIVILEGE           (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     (3L)
#define SE_LOCK_MEMORY_PRIVILEGE            (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE         (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE        (6L)
#define SE_TCB_PRIVILEGE                    (7L)
#define SE_SECURITY_PRIVILEGE               (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE         (9L)
#define SE_LOAD_DRIVER_PRIVILEGE            (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE         (11L)
#define SE_SYSTEMTIME_PRIVILEGE             (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE      (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE        (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE       (16L)
#define SE_BACKUP_PRIVILEGE                 (17L)
#define SE_RESTORE_PRIVILEGE                (18L)
#define SE_SHUTDOWN_PRIVILEGE               (19L)
#define SE_DEBUG_PRIVILEGE                  (20L)
#define SE_AUDIT_PRIVILEGE                  (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE          (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        (24L)
#define SE_UNDOCK_PRIVILEGE                 (25L)
#define SE_SYNC_AGENT_PRIVILEGE             (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE      (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE          (28L)
#define SE_IMPERSONATE_PRIVILEGE            (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE          (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE                (32L)
#define SE_INC_WORKING_SET_PRIVILEGE        (33L)
#define SE_TIME_ZONE_PRIVILEGE              (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   (35L)
#endif

typedef USHORT RTL_ATOM, * PRTL_ATOM;
typedef enum _ATOM_INFORMATION_CLASS {
    AtomBasicInformation,
    AtomTableInformation
} ATOM_INFORMATION_CLASS, * PATOM_INFORMATION_CLASS;
typedef struct _ATOM_BASIC_INFORMATION {
    USHORT                  UsageCount;
    USHORT                  Flags;
    USHORT                  NameLength;
    WCHAR                   Name[1];
} ATOM_BASIC_INFORMATION, * PATOM_BASIC_INFORMATION;
typedef struct _ATOM_TABLE_INFORMATION {
    ULONG                   NumberOfAtoms;
    RTL_ATOM                Atoms[1];
} ATOM_TABLE_INFORMATION, * PATOM_TABLE_INFORMATION;


typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY
    ThreadBasePriority, // s: LONG
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: PVOID
    ThreadZeroTlsCell, // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState,
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority,
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // q: WOW64_CONTEXT
    ThreadGroupInformation, // q: GROUP_AFFINITY // 30
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
    ThreadCpuAccountingInformation, // since WIN8
    ThreadSuspendCount, // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation,
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // since THRESHOLD2
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // s
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented
    SystemRangeStartInformation, // q // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q
    SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q
    SystemComPlusPackage, // q; s
    SystemNumaAvailableMemory, // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
    SystemEmulationBasicInformation, // q
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s
    SystemObjectSecurityMode, // q // 70
    SystemWatchdogTimerHandler, // s (kernel-mode only)
    SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
    SystemFirmwareTableInformation, // not implemented
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
    SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q; s (kernel-mode only)
    SystemVerifierInformationEx, // q; s
    SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
    SystemPrefetchPatchInformation, // not implemented
    SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
    SystemNumaProximityNodeInformation, // q
    SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s
    SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
    SystemStoreInformation, // q; s // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
    SystemNativeBasicInformation, // not implemented
    SystemSpare1, // not implemented
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // since WIN8
    SystemBootGraphicsInformation,
    SystemScrubPhysicalMemoryInformation,
    SystemBadPageInformation,
    SystemProcessorProfileControlArea,
    SystemCombinePhysicalMemoryInformation, // 130
    SystemEntropyInterruptTimingCallback,
    SystemConsoleInformation,
    SystemPlatformBinaryInformation,
    SystemThrottleNotificationInformation,
    SystemHypervisorProcessorCountInformation,
    SystemDeviceDataInformation,
    SystemDeviceDataEnumerationInformation,
    SystemMemoryTopologyInformation,
    SystemMemoryChannelInformation,
    SystemBootLogoInformation, // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
    SystemSpare0,
    SystemSecureBootPolicyInformation,
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation,
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation,
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation,
    SystemElamCertificateInformation,
    SystemOfflineDumpConfigInformation,
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation,
    SystemEdidInformation,
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags,
    SystemCodeIntegrityPolicyInformation,
    SystemIsolatedUserModeInformation,
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,
    SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
    SystemInterruptCpuSetsInformation,
    SystemSecureBootPolicyFullInformation,
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1, // FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation, // FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation, // FILE_BOTH_DIR_INFORMATION
    FileBasicInformation, // FILE_BASIC_INFORMATION
    FileStandardInformation, // FILE_STANDARD_INFORMATION
    FileInternalInformation, // FILE_INTERNAL_INFORMATION
    FileEaInformation, // FILE_EA_INFORMATION
    FileAccessInformation, // FILE_ACCESS_INFORMATION
    FileNameInformation, // FILE_NAME_INFORMATION
    FileRenameInformation, // FILE_RENAME_INFORMATION // 10
    FileLinkInformation, // FILE_LINK_INFORMATION
    FileNamesInformation, // FILE_NAMES_INFORMATION
    FileDispositionInformation, // FILE_DISPOSITION_INFORMATION
    FilePositionInformation, // FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // FILE_MODE_INFORMATION
    FileAlignmentInformation, // FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // FILE_ALL_INFORMATION
    FileAllocationInformation, // FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation, // FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation, // FILE_NAME_INFORMATION
    FileStreamInformation, // FILE_STREAM_INFORMATION
    FilePipeInformation, // FILE_PIPE_INFORMATION
    FilePipeLocalInformation, // FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation, // FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation, // FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // FILE_OBJECTID_INFORMATION
    FileCompletionInformation, // FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation, // FILE_QUOTA_INFORMATION
    FileReparsePointInformation, // FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation, // FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation, // FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation, // FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation, // FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation, // FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation, // FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation, // FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation, // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation, // FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX
    FileSfioReserveInformation, // FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation, // FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation, // FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation, // FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation, // FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,
    FileNumaNodeInformation, // FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation, // FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // FILE_ID_EXTD_DIR_INFORMATION // 60
    FileReplaceCompletionInformation, // FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx, // FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx, // FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation, // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation, // FILE_STAT_INFORMATION
    FileMemoryPartitionInformation, // FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation, // FILE_STAT_LX_INFORMATION // since REDSTONE4 // 70
    FileCaseSensitiveInformation, // FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx, // FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation, // FILE_SET_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck, // FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation, // FILE_KNOWN_FOLDER_INFORMATION // since WIN11
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

typedef enum _HARDERROR_RESPONSE_OPTION {
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, * PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes
} HARDERROR_RESPONSE, * PHARDERROR_RESPONSE;

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation = 1,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

typedef struct _FILE_RENAME_INFORMATION {
    union {
        BOOLEAN ReplaceIfExists;  // FileRenameInformation
        ULONG Flags;              // FileRenameInformationEx
    } DUMMYUNIONNAME;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[255];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    union
    {
        UCHAR Data[1];
        ULONG ULong;
    };
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT Reserved;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    ANSI_STRING         DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    ULONG Flags;
}RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;                     // Number of bits in bit map
    PULONG Buffer;                          // Pointer to the bit map itself
} RTL_BITMAP, * PRTL_BITMAP;


typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               EntryInProgress;
    BOOLEAN             ShutdownInProgress;
    HANDLE              ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY      InLoadOrderLinks;
    LIST_ENTRY      InMemoryOrderLinks;
    LIST_ENTRY      InInitializationOrderLinks;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG_PTR       SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
}TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    TEB_ACTIVE_FRAME_CONTEXT* Context;
}TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
}ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset : 31;
    ULONG HasRenderingCommand : 1;
    ULONG_PTR HDC;
    ULONG Buffer[310];
}GDI_TEB_BATCH, * PGDI_TEB_BATCH;

#ifndef _WINNT_
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        PVOID FiberData;
        ULONG Version;
    };
#else
    PVOID FiberData;
#endif
    PVOID ArbitraryUserPointer;
    struct _NT_TIB* Self;
} NT_TIB, * PNT_TIB;
#endif

typedef struct _RTL_USER_PROCESS_PARAMETERS                                 /* win32/win64 */
{
    ULONG                   MaximumLength;                                  /* 00000/00000 */
    ULONG                   Length;                                         /* 00004/00004 */
    ULONG                   Flags;                                          /* 00008/00008 */
    ULONG                   DebugFlags;                                     /* 0000C/0000C */
    HANDLE                  ConsoleHandle;                                  /* 00010/00010 */
    ULONG                   ConsoleFlags;                                   /* 00014/00018 */
    HANDLE                  StandardInput;                                  /* 00018/00020 */
    HANDLE                  StandardOutput;                                 /* 0001C/00028 */
    HANDLE                  StandardError;                                  /* 00020/00030 */
    CURDIR                  CurrentDirectory;                               /* 00024/00038 */
    UNICODE_STRING          DllPath;                                        /* 00000/00050 */
    UNICODE_STRING          ImagePathName;                                  /* 00000/00060 */
    UNICODE_STRING          CommandLine;                                    /* 00000/00070 */
    PVOID                   Environment;                                    /* 00000/00080 */
    ULONG                   StartingX;                                      /* 00000/00088 */
    ULONG                   StartingY;                                      /* 00000/0008C */
    ULONG                   CountX;                                         /* 00000/00090 */
    ULONG                   CountY;                                         /* 00000/00094 */
    ULONG                   CountCharsX;                                    /* 00000/00098 */
    ULONG                   CountCharsY;                                    /* 00000/0009C */
    ULONG                   FillAttribute;                                  /* 00000/000A0 */
    ULONG                   WindowFlags;                                    /* 00000/000A4 */
    ULONG                   ShowWindowFlags;                                /* 00000/000A8 */
    UNICODE_STRING          WindowTitle;                                    /* 00000/000B0 */
    UNICODE_STRING          DesktopInfo;                                    /* 00000/000C0 */
    UNICODE_STRING          ShellInfo;                                      /* 00000/000D0 */
    UNICODE_STRING          RuntimeInfo;                                    /* 00000/000E0 */
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[32];                         /* 00000/000F0 */
    ULONG_PTR               EnvironmentSize;                                /* 00000/003F0 */
    ULONG_PTR               EnvironmentVersion;                             /* 00000/003F8 */
    PVOID                   PackageDependencyData;                          /* 00000/00400 */
    ULONG                   ProcessGroupId;                                 /* 00000/00408 */
    ULONG                   LoaderThreads;                                  /* 00000/0040C */
    UNICODE_STRING          RedirectionDllName;                             /* 00000/00410 */
    UNICODE_STRING          HeapPartitionName;                              /* 00000/00420 */
    PULONG_PTR              DefaultThreadpoolCpuSetMasks;                   /* 00000/00430 */
    ULONG                   DefaultThreadpoolCpuSetMaskCount;               /* 00000/00438 */
    ULONG                   DefaultThreadpoolThreadMaximum;                 /* 00000/0043C */
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{                                                                           /* win32/win64 */
    BOOLEAN                         InheritedAddressSpace;                  /* 00000/00000 */
    BOOLEAN                         ReadImageFileExecOptions;               /* 00001/00001 */
    BOOLEAN                         BeingDebugged;                          /* 00002/00002 */
    union
    {
        BOOLEAN                     BitField;                               /* 00003/00003 */
        struct
        {
            BOOLEAN                 ImageUsesLargePages : 1;
            BOOLEAN                 IsProtectedProcess : 1;
            BOOLEAN                 IsImageDynamicallyRelocated : 1;
            BOOLEAN                 SkipPatchingUser32Forwarders : 1;
            BOOLEAN                 IsPackagedProcess : 1;
            BOOLEAN                 IsAppContainer : 1;
            BOOLEAN                 IsProtectedProcessLight : 1;
            BOOLEAN                 IsLongPathAwareProcess : 1;
        };
    };
    HANDLE                          Mutant;                                 /* 00004/00008 */
    PVOID                           ImageBaseAddress;                       /* 00008/00010 */
    PPEB_LDR_DATA                   Ldr;                                    /* 0000C/00018 */
    PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;                      /* 00010/00020 */
    PVOID                           SubSystemData;                          /* 00014/00028 */
    PVOID                           ProcessHeap;                            /* 00018/00030 */
    PVOID /*PRTL_CRITICAL_SECTION*/ FastPebLock;                            /* 0001c/00038 */
    PVOID /*PPEBLOCKROUTINE*/       FastPebLockRoutine;                     /* 00020/00040 */
    PVOID /*PPEBLOCKROUTINE*/       FastPebUnlockRoutine;                   /* 00024/00048 */
    ULONG                           EnvironmentUpdateCount;                 /* 00028/00050 */
    PVOID                           KernelCallbackTable;                    /* 0002C/00058 */
    ULONG                           Reserved[2];                            /* 00030/00060 */
    PVOID /*PPEB_FREE_BLOCK*/       FreeList;                               /* 00038/00068 */
    ULONG                           TlsExpansionCounter;                    /* 0003C/00070 */
    PRTL_BITMAP                     TlsBitmap;                              /* 00040/00078 */
    ULONG                           TlsBitmapBits[2];                       /* 00044/00080 */
    PVOID                           ReadOnlySharedMemoryBase;               /* 0004C/00088 */
    PVOID                           ReadOnlySharedMemoryHeap;               /* 00050/00090 */
    PVOID* ReadOnlyStaticServerData;               /* 00054/00098 */
    PVOID                           AnsiCodePageData;                       /* 00058/000A0 */
    PVOID                           OemCodePageData;                        /* 0005C/000A8 */
    PVOID                           UnicodeCaseTableData;                   /* 00060/000B0 */
    ULONG                           NumberOfProcessors;                     /* 00064/000B8 */
    ULONG                           NtGlobalFlag;                           /* 00068/000BC */
    LARGE_INTEGER                   CriticalSectionTimeout;                 /* 00070/000C0 */
    ULONG_PTR                       HeapSegmentReserve;                     /* 00078/000C8 */
    ULONG_PTR                       HeapSegmentCommit;                      /* 0007C/000D0 */
    ULONG_PTR                       HeapDeCommitTotalFreeThreshold;         /* 00080/000D8 */
    ULONG_PTR                       HeapDeCommitFreeBlockThreshold;         /* 00084/000E0 */
    ULONG                           NumberOfHeaps;                          /* 00088/000E8 */
    ULONG                           MaximumNumberOfHeaps;                   /* 0008C/000EC */
    PVOID* ProcessHeaps;                           /* 00090/000F0 */
    PVOID                           GdiSharedHandleTable;                   /* 00094/000F8 */
    PVOID                           ProcessStarterHelper;                   /* 00098/00100 */
    PVOID                           GdiDCAttributeList;                     /* 0009C/00108 */
    PVOID                           LoaderLock;                             /* 000A0/00110 */
    ULONG                           OSMajorVersion;                         /* 000A4/00118 */
    ULONG                           OSMinorVersion;                         /* 000A8/0011C */
    SHORT                           OSBuildNumber;                          /* 000AC/00120 */
    ULONG                           OSPlatformId;                           /* 000B0/00124 */
    ULONG                           ImageSubSystem;                         /* 000B4/00128 */
    ULONG                           ImageSubSystemMajorVersion;             /* 000B8/0012C */
    ULONG                           ImageSubSystemMinorVersion;             /* 000BC/00130 */
    ULONG                           ImageProcessAffinityMask;               /* 000C0/00134 */
    HANDLE                          GdiHandleBuffer[28];                    /* 000C4/00138 */
    ULONG                           unknown[6];                             /* 00134/00218 */
    PVOID                           PostProcessInitRoutine;                 /* 0014C/00230 */
    PRTL_BITMAP                     TlsExpansionBitmap;                     /* 00150/00238 */
    ULONG                           TlsExpansionBitmapBits[32];             /* 00154/00240 */
    ULONG                           SessionId;                              /* 001D4/002C0 */
}PEB, * PPEB;

typedef struct _TEB
{                                                                           /* win32/win64 */
    NT_TIB                          Tib;                                    /* 00000/00000 */
    PVOID                           EnvironmentPointer;                     /* 0001C/00038 */
    CLIENT_ID                       ClientId;                               /* 00020/00040 */
    PVOID                           ActiveRpcHandle;                        /* 00028/00050 */
    PVOID* ThreadLocalStoragePointer;              /* 0002C/00058 */
    PPEB                            Peb;                                    /* 00030/00060 */
    union
    {
        ULONG                       LastErrorValue;                         /* 00034/00068 */
        ULONG                       SystemCallNumber;                       /* 00034/00068 */
    };
    ULONG                           CountOfOwnedCriticalSections;           /* 00038/0006C */
    PVOID                           CsrClientThread;                        /* 0003C/00070 */
    PVOID                           Win32ThreadInfo;                        /* 00040/00078 */
    ULONG                           Win32ClientInfo[31];                    /* 00044/00080 used for user32 private data in Wine */
    PVOID                           WOW32Reserved;                          /* 000C0/00100 */
    ULONG                           CurrentLocale;                          /* 000C4/00108 */
    ULONG                           FpSoftwareStatusRegister;               /* 000C8/0010C */
    PVOID                           SystemReserved1[54];                    /* 000CC/00110 used for kernel32 private data in Wine */
    LONG                            ExceptionCode;                          /* 001A4/002C0 */
    ACTIVATION_CONTEXT_STACK        ActivationContextStack;                 /* 001A8/002C8 */
    UCHAR                           SpareBytes1[24];                        /* 001BC/002E8 */
    PVOID                           SystemReserved2[10];                    /* 001D4/00300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH                   GdiTebBatch;                            /* 001FC/00350 used for ntdll private data in Wine */
    HANDLE                          gdiRgn;                                 /* 006DC/00838 */
    HANDLE                          gdiPen;                                 /* 006E0/00840 */
    HANDLE                          gdiBrush;                               /* 006E4/00848 */
    CLIENT_ID                       RealClientId;                           /* 006E8/00850 */
    HANDLE                          GdiCachedProcessHandle;                 /* 006F0/00860 */
    ULONG                           GdiClientPID;                           /* 006F4/00868 */
    ULONG                           GdiClientTID;                           /* 006F8/0086C */
    PVOID                           GdiThreadLocaleInfo;                    /* 006FC/00870 */
    ULONG                           UserReserved[5];                        /* 00700/00878 */
    PVOID                           glDispatchTable[280];                   /* 00714/00890 */
    PVOID                           glReserved1[26];                        /* 00B74/01150 */
    PVOID                           glReserved2;                            /* 00BDC/01220 */
    PVOID                           glSectionInfo;                          /* 00BE0/01228 */
    PVOID                           glSection;                              /* 00BE4/01230 */
    PVOID                           glTable;                                /* 00BE8/01238 */
    PVOID                           glCurrentRC;                            /* 00BEC/01240 */
    PVOID                           glContext;                              /* 00BF0/01248 */
    ULONG                           LastStatusValue;                        /* 00BF4/01250 */
    UNICODE_STRING                  StaticUnicodeString;                    /* 00BF8/01258 used by advapi32 */
    WCHAR                           StaticUnicodeBuffer[261];               /* 00C00/01268 used by advapi32 */
    PVOID                           DeallocationStack;                      /* 00E0C/01478 */
    PVOID                           TlsSlots[64];                           /* 00E10/01480 */
    LIST_ENTRY                      TlsLinks;                               /* 00F10/01680 */
    PVOID                           Vdm;                                    /* 00F18/01690 */
    PVOID                           ReservedForNtRpc;                       /* 00F1C/01698 */
    PVOID                           DbgSsReserved[2];                       /* 00F20/016A0 */
    ULONG                           HardErrorDisabled;                      /* 00F28/016B0 */
    PVOID                           Instrumentation[16];                    /* 00F2C/016B8 */
    PVOID                           WinSockData;                            /* 00F6C/01738 */
    ULONG                           GdiBatchCount;                          /* 00F70/01740 */
    ULONG                           Spare2;                                 /* 00F74/01744 */
    ULONG                           GuaranteedStackBytes;                   /* 00F78/01748 */
    PVOID                           ReservedForPerf;                        /* 00F7C/01750 */
    PVOID                           ReservedForOle;                         /* 00F80/01758 */
    ULONG                           WaitingOnLoaderLock;                    /* 00F84/01760 */
    PVOID                           Reserved5[3];                           /* 00F88/01768 */
    PVOID* TlsExpansionSlots;                      /* 00F94/01780 */
#ifdef _WIN64
    PVOID                           DeallocationBStore;                     /* 00000/01788 */
    PVOID                           BStoreLimit;                            /* 00000/01790 */
#endif
    ULONG                           ImpersonationLocale;                    /* 00F98/01798 */
    ULONG                           IsImpersonating;                        /* 00F9C/0179C */
    PVOID                           NlsCache;                               /* 00FA0/017A0 */
    PVOID                           ShimData;                               /* 00FA4/017A8 */
    ULONG                           HeapVirtualAffinity;                    /* 00FA8/017B0 */
    PVOID                           CurrentTransactionHandle;               /* 00FAc/017B8 */
    TEB_ACTIVE_FRAME* ActiveFrame;                            /* 00FB0/017C0 */
} TEB, * PTEB;

typedef struct _LPC_MESSAGE {
    USHORT                  DataLength;
    USHORT                  Length;
    USHORT                  MessageType;
    USHORT                  DataInfoOffset;
    CLIENT_ID               ClientId;
    ULONG                   MessageId;
    ULONG                   CallbackId;
} LPC_MESSAGE, * PLPC_MESSAGE;
typedef struct _LPC_SECTION_OWNER_MEMORY {
    ULONG                   Length;
    HANDLE                  SectionHandle;
    ULONG                   OffsetInSection;
    ULONG                   ViewSize;
    PVOID                   ViewBase;
    PVOID                   OtherSideViewBase;
} LPC_SECTION_OWNER_MEMORY, * PLPC_SECTION_OWNER_MEMORY;
typedef struct _LPC_SECTION_MEMORY {
    ULONG                   Length;
    ULONG                   ViewSize;
    PVOID                   ViewBase;
} LPC_SECTION_MEMORY, * PLPC_SECTION_MEMORY;















typedef struct _NT_TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[16];
} NT_TOKEN_PRIVILEGES, * PNT_TOKEN_PRIVILEGES;


typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    ULONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef VOID(NTAPI* PIO_APC_ROUTINE) (IN PVOID ApcContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG Reserved);

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#if defined _M_IX86
#define __readtebptr(offset)  __readfsdword(offset)
#define __readtebdword(offset)  __readfsdword(offset)
#define __writetebdword(offset, value)  __writefsdword(offset, value)
#elif defined _M_X64
#define __readtebptr(offset)  __readgsqword(offset)
#define __readtebdword(offset)  __readgsdword(offset)
#define __writetebdword(offset, value)  __writegsdword(offset, value)
#endif

#ifndef NtSetLastError
#define NtSetLastError(error) __writetebdword(UFIELD_OFFSET(TEB, LastErrorValue), (ULONG)(error))
#define NtGetLastError() __readtebdword(UFIELD_OFFSET(TEB, LastErrorValue))
#endif
#ifndef NtSetCurrentLocale
#define NtSetCurrentLocale(locale) __writetebdword(UFIELD_OFFSET(TEB, CurrentLocale), locale)
#define NtGetCurrentLocale() __readtebdword(UFIELD_OFFSET(TEB, CurrentLocale))
#endif
#ifndef NtSetExceptionCode
#define NtSetExceptionCode(code) __writetebdword(UFIELD_OFFSET(TEB, ExceptionCode), code)
#define NtGetExceptionCode() __readtebdword(UFIELD_OFFSET(TEB, ExceptionCode))
#endif
#ifndef NtCurrentTeb
#define NtCurrentTeb() ((PTEB)__readtebptr(UFIELD_OFFSET(NT_TIB, Self)))
#define NtCurrentPeb() ((PPEB)__readtebptr(UFIELD_OFFSET(TEB, Peb)))
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef GetCurrentProcess
#define GetCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef GetCurrentThread
#define GetCurrentThread() ((HANDLE)(LONG_PTR)-2)
#endif
#ifndef GetCurrentProcessId
#define GetCurrentProcessId() NtCurrentTeb()->ClientId.UniqueProcess
#endif
#ifndef GetCurrentThreadId
#define GetCurrentThreadId() NtCurrentTeb()->ClientId.UniqueThread
#endif
#ifndef PebBuildNumber
#define PebBuildNumber NtCurrentPeb()->OSBuildNumber
#endif

#ifndef __ROL1__
#define __ROL1__ _rotl8
#define __ROR1__ _rotr8
#define __ROL2__ _rotl16
#define __ROR2__ _rotr16
#define __ROL4__ _rotl
#define __ROR4__ _rotr
#define __ROL8__ _rotl64
#define __ROR8__ _rotr64
#endif

/*
[InLoadOrderModuleList]
Server.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
apphelp.dll
[InMemoryOrderModuleList]
Server.exe
ntdll.dll
KERNEL32.DLL
KERNELBASE.dll
apphelp.dll
[InInitializationOrderModuleList]
ntdll.dll
KERNELBASE.dll
KERNEL32.DLL
apphelp.dll
*/