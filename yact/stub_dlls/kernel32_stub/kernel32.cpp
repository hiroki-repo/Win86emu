#include "dllstub_def.h"

static const char DLL_NAME[]="kernel32.nt.dll";

DEFINE_FUNC2(RtlZeroMemory)
DEFINE_FUNC3(RtlMoveMemory)
DEFINE_FUNC_ORD1(AcquireSRWLockExclusive,1)		// Some protectors use fake import by ordinal number 1
DEFINE_FUNC1(AcquireSRWLockShared)
DEFINE_FUNC2(ActivateActCtx)
DEFINE_FUNC1(AddAtomA)
DEFINE_FUNC1(AddAtomW)
DEFINE_FUNC3(AddConsoleAliasA)
DEFINE_FUNC3(AddConsoleAliasW)
DEFINE_FUNC2(AddLocalAlternateComputerNameA)
DEFINE_FUNC2(AddLocalAlternateComputerNameW)
DEFINE_FUNC1(AddRefActCtx)
DEFINE_FUNC2(AddSIDToBoundaryDescriptor)
DEFINE_FUNC2(AddVectoredContinueHandler)
DEFINE_FUNC2(AddVectoredExceptionHandler)
DEFINE_FUNC0(AllocConsole)
DEFINE_FUNC3(AllocateUserPhysicalPages)
DEFINE_FUNC4(AllocateUserPhysicalPagesNuma)
DEFINE_FUNC1(ApplicationRecoveryFinished)
DEFINE_FUNC1(ApplicationRecoveryInProgress)
DEFINE_FUNC0(AreFileApisANSI)
DEFINE_FUNC2(AssignProcessToJobObject)
DEFINE_FUNC1(AttachConsole)
DEFINE_FUNC7(BackupRead)
DEFINE_FUNC6(BackupSeek)
DEFINE_FUNC7(BackupWrite)
DEFINE_FUNC2(Beep)
DEFINE_FUNC2(BeginUpdateResourceA)
DEFINE_FUNC2(BeginUpdateResourceW)
DEFINE_FUNC3(BindIoCompletionCallback)
DEFINE_FUNC2(BuildCommDCBA)
DEFINE_FUNC3(BuildCommDCBAndTimeoutsA)
DEFINE_FUNC3(BuildCommDCBAndTimeoutsW)
DEFINE_FUNC2(BuildCommDCBW)
DEFINE_FUNC7(CallNamedPipeA)
DEFINE_FUNC7(CallNamedPipeW)
DEFINE_FUNC1(CallbackMayRunLong)
DEFINE_FUNC1(CancelDeviceWakeupRequest)
DEFINE_FUNC1(CancelIo)
DEFINE_FUNC2(CancelIoEx)
DEFINE_FUNC1(CancelSynchronousIo)
DEFINE_FUNC1(CancelThreadpoolIo)
DEFINE_FUNC2(CancelTimerQueueTimer)
DEFINE_FUNC1(CancelWaitableTimer)
DEFINE_FUNC4(ChangeTimerQueueTimer)
DEFINE_FUNC5(CheckNameLegalDOS8Dot3A)
DEFINE_FUNC5(CheckNameLegalDOS8Dot3W)
DEFINE_FUNC2(CheckRemoteDebuggerPresent)
DEFINE_FUNC1(ClearCommBreak)
DEFINE_FUNC3(ClearCommError)
DEFINE_FUNC1(CloseHandle)
DEFINE_FUNC2(ClosePrivateNamespace)
DEFINE_FUNC1(CloseThreadpool)
DEFINE_FUNC1(CloseThreadpoolCleanupGroup)
DEFINE_FUNC3(CloseThreadpoolCleanupGroupMembers)
DEFINE_FUNC1(CloseThreadpoolIo)
DEFINE_FUNC1(CloseThreadpoolTimer)
DEFINE_FUNC1(CloseThreadpoolWait)
DEFINE_FUNC1(CloseThreadpoolWork)
DEFINE_FUNC3(CommConfigDialogA)
DEFINE_FUNC3(CommConfigDialogW)
DEFINE_FUNC2(CompareFileTime)
DEFINE_FUNC6(CompareStringA)
DEFINE_FUNC9(CompareStringEx)
DEFINE_FUNC5(CompareStringOrdinal)
DEFINE_FUNC6(CompareStringW)
DEFINE_FUNC2(ConnectNamedPipe)
DEFINE_FUNC3(ContinueDebugEvent)
DEFINE_FUNC1(ConvertDefaultLocale)
DEFINE_FUNC0(ConvertFiberToThread)
DEFINE_FUNC1(ConvertThreadToFiber)
DEFINE_FUNC2(ConvertThreadToFiberEx)
DEFINE_FUNC3(CopyFileA)
DEFINE_FUNC6(CopyFileExA)
DEFINE_FUNC6(CopyFileExW)
DEFINE_FUNC7(CopyFileTransactedA)
DEFINE_FUNC7(CopyFileTransactedW)
DEFINE_FUNC3(CopyFileW)
DEFINE_FUNC1(CreateActCtxA)
DEFINE_FUNC1(CreateActCtxW)
DEFINE_FUNC2(CreateBoundaryDescriptorA)
DEFINE_FUNC2(CreateBoundaryDescriptorW)
DEFINE_FUNC5(CreateConsoleScreenBuffer)
DEFINE_FUNC2(CreateDirectoryA)
DEFINE_FUNC3(CreateDirectoryExA)
DEFINE_FUNC3(CreateDirectoryExW)
DEFINE_FUNC4(CreateDirectoryTransactedA)
DEFINE_FUNC4(CreateDirectoryTransactedW)
DEFINE_FUNC2(CreateDirectoryW)
DEFINE_FUNC4(CreateEventA)
DEFINE_FUNC4(CreateEventExA)
DEFINE_FUNC4(CreateEventExW)
DEFINE_FUNC4(CreateEventW)
DEFINE_FUNC3(CreateFiber)
DEFINE_FUNC5(CreateFiberEx)
DEFINE_FUNC7(CreateFileA)
DEFINE_FUNC6(CreateFileMappingA)
DEFINE_FUNC7(CreateFileMappingNumaA)
DEFINE_FUNC7(CreateFileMappingNumaW)
DEFINE_FUNC6(CreateFileMappingW)
DEFINE_FUNC10(CreateFileTransactedA)
DEFINE_FUNC10(CreateFileTransactedW)
DEFINE_FUNC7(CreateFileW)
DEFINE_FUNC3(CreateHardLinkA)
DEFINE_FUNC4(CreateHardLinkTransactedA)
DEFINE_FUNC4(CreateHardLinkTransactedW)
DEFINE_FUNC3(CreateHardLinkW)
DEFINE_FUNC4(CreateIoCompletionPort)
DEFINE_FUNC2(CreateJobObjectA)
DEFINE_FUNC2(CreateJobObjectW)
DEFINE_FUNC3(CreateJobSet)
DEFINE_FUNC4(CreateMailslotA)
DEFINE_FUNC4(CreateMailslotW)
DEFINE_FUNC1(CreateMemoryResourceNotification)
DEFINE_FUNC3(CreateMutexA)
DEFINE_FUNC4(CreateMutexExA)
DEFINE_FUNC4(CreateMutexExW)
DEFINE_FUNC3(CreateMutexW)
DEFINE_FUNC8(CreateNamedPipeA)
DEFINE_FUNC8(CreateNamedPipeW)
DEFINE_FUNC4(CreatePipe)
DEFINE_FUNC3(CreatePrivateNamespaceA)
DEFINE_FUNC3(CreatePrivateNamespaceW)
DEFINE_FUNC10(CreateProcessA)
DEFINE_FUNC10(CreateProcessW)
DEFINE_FUNC7(CreateRemoteThread)
DEFINE_FUNC4(CreateSemaphoreA)
DEFINE_FUNC6(CreateSemaphoreExA)
DEFINE_FUNC6(CreateSemaphoreExW)
DEFINE_FUNC4(CreateSemaphoreW)
DEFINE_FUNC3(CreateSymbolicLinkA)
DEFINE_FUNC4(CreateSymbolicLinkTransactedA)
DEFINE_FUNC4(CreateSymbolicLinkTransactedW)
DEFINE_FUNC3(CreateSymbolicLinkW)
DEFINE_FUNC4(CreateTapePartition)
DEFINE_FUNC6(CreateThread)
DEFINE_FUNC1(CreateThreadpool)
DEFINE_FUNC0(CreateThreadpoolCleanupGroup)
DEFINE_FUNC4(CreateThreadpoolIo)
DEFINE_FUNC3(CreateThreadpoolTimer)
DEFINE_FUNC3(CreateThreadpoolWait)
DEFINE_FUNC3(CreateThreadpoolWork)
DEFINE_FUNC0(CreateTimerQueue)
DEFINE_FUNC7(CreateTimerQueueTimer)
DEFINE_FUNC2(CreateToolhelp32Snapshot)
DEFINE_FUNC3(CreateWaitableTimerA)
DEFINE_FUNC4(CreateWaitableTimerExA)
DEFINE_FUNC4(CreateWaitableTimerExW)
DEFINE_FUNC3(CreateWaitableTimerW)
DEFINE_FUNC2(DeactivateActCtx)
DEFINE_FUNC1(DebugActiveProcess)
DEFINE_FUNC1(DebugActiveProcessStop)
DEFINE_FUNC0(DebugBreak)
DEFINE_FUNC1(DebugBreakProcess)
DEFINE_FUNC1(DebugSetProcessKillOnExit)
DEFINE_FUNC1(DecodeSystemPointer)
DEFINE_FUNC3(DefineDosDeviceA)
DEFINE_FUNC3(DefineDosDeviceW)
DEFINE_FUNC1(DeleteAtom)
DEFINE_FUNC1(DeleteBoundaryDescriptor)
DEFINE_FUNC1(DeleteCriticalSection)
DEFINE_FUNC1(DeleteFiber)
DEFINE_FUNC1(DeleteFileA)
DEFINE_FUNC2(DeleteFileTransactedA)
DEFINE_FUNC2(DeleteFileTransactedW)
DEFINE_FUNC1(DeleteFileW)
DEFINE_FUNC1(DeleteProcThreadAttributeList)
DEFINE_FUNC1(DeleteTimerQueue)
DEFINE_FUNC2(DeleteTimerQueueEx)
DEFINE_FUNC3(DeleteTimerQueueTimer)
DEFINE_FUNC1(DeleteVolumeMountPointA)
DEFINE_FUNC1(DeleteVolumeMountPointW)
DEFINE_FUNC8(DeviceIoControl)
DEFINE_FUNC1(DisableThreadLibraryCalls)
DEFINE_FUNC1(DisassociateCurrentThreadFromCallback)
DEFINE_FUNC1(DisconnectNamedPipe)
DEFINE_FUNC3(DnsHostnameToComputerNameA)
DEFINE_FUNC3(DnsHostnameToComputerNameW)
DEFINE_FUNC3(DosDateTimeToFileTime)
DEFINE_FUNC7(DuplicateHandle)
DEFINE_FUNC1(EncodeSystemPointer)
DEFINE_FUNC2(EndUpdateResourceA)
DEFINE_FUNC2(EndUpdateResourceW)
DEFINE_FUNC1(EnterCriticalSection)
DEFINE_FUNC4(EnumCalendarInfoA)
DEFINE_FUNC4(EnumCalendarInfoExA)
DEFINE_FUNC6(EnumCalendarInfoExEx)
DEFINE_FUNC4(EnumCalendarInfoExW)
DEFINE_FUNC4(EnumCalendarInfoW)
DEFINE_FUNC3(EnumDateFormatsA)
DEFINE_FUNC3(EnumDateFormatsExA)
DEFINE_FUNC4(EnumDateFormatsExEx)
DEFINE_FUNC3(EnumDateFormatsExW)
DEFINE_FUNC3(EnumDateFormatsW)
DEFINE_FUNC4(EnumLanguageGroupLocalesA)
DEFINE_FUNC4(EnumLanguageGroupLocalesW)
DEFINE_FUNC5(EnumResourceLanguagesA)
DEFINE_FUNC7(EnumResourceLanguagesExA)
DEFINE_FUNC7(EnumResourceLanguagesExW)
DEFINE_FUNC5(EnumResourceLanguagesW)
DEFINE_FUNC4(EnumResourceNamesA)
DEFINE_FUNC6(EnumResourceNamesExA)
DEFINE_FUNC6(EnumResourceNamesExW)
DEFINE_FUNC4(EnumResourceNamesW)
DEFINE_FUNC3(EnumResourceTypesA)
DEFINE_FUNC5(EnumResourceTypesExA)
DEFINE_FUNC5(EnumResourceTypesExW)
DEFINE_FUNC3(EnumResourceTypesW)
DEFINE_FUNC2(EnumSystemCodePagesA)
DEFINE_FUNC2(EnumSystemCodePagesW)
DEFINE_FUNC3(EnumSystemFirmwareTables)
DEFINE_FUNC3(EnumSystemGeoID)
DEFINE_FUNC3(EnumSystemLanguageGroupsA)
DEFINE_FUNC3(EnumSystemLanguageGroupsW)
DEFINE_FUNC2(EnumSystemLocalesA)
DEFINE_FUNC4(EnumSystemLocalesEx)
DEFINE_FUNC2(EnumSystemLocalesW)
DEFINE_FUNC3(EnumTimeFormatsA)
DEFINE_FUNC4(EnumTimeFormatsEx)
DEFINE_FUNC3(EnumTimeFormatsW)
DEFINE_FUNC3(EnumUILanguagesA)
DEFINE_FUNC3(EnumUILanguagesW)
DEFINE_FUNC4(EnumerateLocalComputerNamesA)
DEFINE_FUNC4(EnumerateLocalComputerNamesW)
DEFINE_FUNC3(EraseTape)
DEFINE_FUNC2(EscapeCommFunction)
DEFINE_FUNC1(ExitProcess)
DEFINE_FUNC1(ExitThread)
DEFINE_FUNC3(ExpandEnvironmentStringsA)
DEFINE_FUNC3(ExpandEnvironmentStringsW)
DEFINE_FUNC2(FatalAppExitA)
DEFINE_FUNC2(FatalAppExitW)
DEFINE_FUNC1(FatalExit)
DEFINE_FUNC3(FileTimeToDosDateTime)
DEFINE_FUNC2(FileTimeToLocalFileTime)
DEFINE_FUNC2(FileTimeToSystemTime)
DEFINE_FUNC5(FillConsoleOutputAttribute)
DEFINE_FUNC5(FillConsoleOutputCharacterA)
DEFINE_FUNC5(FillConsoleOutputCharacterW)
DEFINE_FUNC5(FindActCtxSectionGuid)
DEFINE_FUNC5(FindActCtxSectionStringA)
DEFINE_FUNC5(FindActCtxSectionStringW)
DEFINE_FUNC1(FindAtomA)
DEFINE_FUNC1(FindAtomW)
DEFINE_FUNC1(FindClose)
DEFINE_FUNC1(FindCloseChangeNotification)
DEFINE_FUNC3(FindFirstChangeNotificationA)
DEFINE_FUNC3(FindFirstChangeNotificationW)
DEFINE_FUNC2(FindFirstFileA)
DEFINE_FUNC6(FindFirstFileExA)
DEFINE_FUNC6(FindFirstFileExW)
DEFINE_FUNC5(FindFirstFileNameTransactedW)
DEFINE_FUNC4(FindFirstFileNameW)
DEFINE_FUNC7(FindFirstFileTransactedA)
DEFINE_FUNC7(FindFirstFileTransactedW)
DEFINE_FUNC2(FindFirstFileW)
DEFINE_FUNC5(FindFirstStreamTransactedW)
DEFINE_FUNC4(FindFirstStreamW)
DEFINE_FUNC2(FindFirstVolumeA)
DEFINE_FUNC3(FindFirstVolumeMountPointA)
DEFINE_FUNC3(FindFirstVolumeMountPointW)
DEFINE_FUNC2(FindFirstVolumeW)
DEFINE_FUNC7(FindNLSString)
DEFINE_FUNC10(FindNLSStringEx)
DEFINE_FUNC1(FindNextChangeNotification)
DEFINE_FUNC2(FindNextFileA)
DEFINE_FUNC3(FindNextFileNameW)
DEFINE_FUNC2(FindNextFileW)
DEFINE_FUNC2(FindNextStreamW)
DEFINE_FUNC3(FindNextVolumeA)
DEFINE_FUNC3(FindNextVolumeMountPointA)
DEFINE_FUNC3(FindNextVolumeMountPointW)
DEFINE_FUNC3(FindNextVolumeW)
DEFINE_FUNC3(FindResourceA)
DEFINE_FUNC4(FindResourceExA)
DEFINE_FUNC4(FindResourceExW)
DEFINE_FUNC3(FindResourceW)
DEFINE_FUNC1(FindVolumeClose)
DEFINE_FUNC1(FindVolumeMountPointClose)
DEFINE_FUNC1(FlsAlloc)
DEFINE_FUNC1(FlsFree)
DEFINE_FUNC1(FlsGetValue)
DEFINE_FUNC2(FlsSetValue)
DEFINE_FUNC1(FlushConsoleInputBuffer)
DEFINE_FUNC1(FlushFileBuffers)
DEFINE_FUNC3(FlushInstructionCache)
DEFINE_FUNC0(FlushProcessWriteBuffers)
DEFINE_FUNC2(FlushViewOfFile)
DEFINE_FUNC5(FoldStringA)
DEFINE_FUNC5(FoldStringW)
DEFINE_FUNC7(FormatMessageA)
DEFINE_FUNC7(FormatMessageW)
DEFINE_FUNC0(FreeConsole)
DEFINE_FUNC1(FreeEnvironmentStringsA)
DEFINE_FUNC1(FreeEnvironmentStringsW)
DEFINE_FUNC1(FreeLibrary)
DEFINE_FUNC2(FreeLibraryAndExitThread)
DEFINE_FUNC2(FreeLibraryWhenCallbackReturns)
DEFINE_FUNC1(FreeResource)
DEFINE_FUNC3(FreeUserPhysicalPages)
DEFINE_FUNC2(GenerateConsoleCtrlEvent)
DEFINE_FUNC0(GetACP)
DEFINE_FUNC5(GetApplicationRecoveryCallback)
DEFINE_FUNC4(GetApplicationRestartSettings)
DEFINE_FUNC3(GetAtomNameA)
DEFINE_FUNC3(GetAtomNameW)
DEFINE_FUNC2(GetBinaryType)
DEFINE_FUNC2(GetBinaryTypeA)
DEFINE_FUNC2(GetBinaryTypeW)
DEFINE_FUNC2(GetCPInfo)
DEFINE_FUNC3(GetCPInfoExA)
DEFINE_FUNC3(GetCPInfoExW)
DEFINE_FUNC6(GetCalendarInfoA)
DEFINE_FUNC7(GetCalendarInfoEx)
DEFINE_FUNC6(GetCalendarInfoW)
DEFINE_FUNC3(GetCommConfig)
DEFINE_FUNC2(GetCommMask)
DEFINE_FUNC2(GetCommModemStatus)
DEFINE_FUNC2(GetCommProperties)
DEFINE_FUNC2(GetCommState)
DEFINE_FUNC2(GetCommTimeouts)
DEFINE_FUNC0(GetCommandLineA)
DEFINE_FUNC0(GetCommandLineW)
DEFINE_FUNC2(GetCompressedFileSizeA)
DEFINE_FUNC3(GetCompressedFileSizeTransactedA)
DEFINE_FUNC3(GetCompressedFileSizeTransactedW)
DEFINE_FUNC2(GetCompressedFileSizeW)
DEFINE_FUNC2(GetComputerNameA)
DEFINE_FUNC3(GetComputerNameExA)
DEFINE_FUNC3(GetComputerNameExW)
DEFINE_FUNC2(GetComputerNameW)
DEFINE_FUNC4(GetConsoleAliasA)
DEFINE_FUNC2(GetConsoleAliasExesA)
DEFINE_FUNC0(GetConsoleAliasExesLengthA)
DEFINE_FUNC0(GetConsoleAliasExesLengthW)
DEFINE_FUNC2(GetConsoleAliasExesW)
DEFINE_FUNC4(GetConsoleAliasW)
DEFINE_FUNC3(GetConsoleAliasesA)
DEFINE_FUNC1(GetConsoleAliasesLengthA)
DEFINE_FUNC1(GetConsoleAliasesLengthW)
DEFINE_FUNC3(GetConsoleAliasesW)
DEFINE_FUNC0(GetConsoleCP)
DEFINE_FUNC2(GetConsoleCursorInfo)
DEFINE_FUNC1(GetConsoleDisplayMode)
DEFINE_FUNC2(GetConsoleFontSize)
DEFINE_FUNC1(GetConsoleHistoryInfo)
DEFINE_FUNC2(GetConsoleMode)
DEFINE_FUNC2(GetConsoleOriginalTitleA)
DEFINE_FUNC2(GetConsoleOriginalTitleW)
DEFINE_FUNC0(GetConsoleOutputCP)
DEFINE_FUNC2(GetConsoleProcessList)
DEFINE_FUNC2(GetConsoleScreenBufferInfo)
DEFINE_FUNC2(GetConsoleScreenBufferInfoEx)
DEFINE_FUNC1(GetConsoleSelectionInfo)
DEFINE_FUNC2(GetConsoleTitleA)
DEFINE_FUNC2(GetConsoleTitleW)
DEFINE_FUNC0(GetConsoleWindow)
DEFINE_FUNC6(GetCurrencyFormatA)
DEFINE_FUNC6(GetCurrencyFormatEx)
DEFINE_FUNC6(GetCurrencyFormatW)
DEFINE_FUNC1(GetCurrentActCtx)
DEFINE_FUNC3(GetCurrentConsoleFont)
DEFINE_FUNC3(GetCurrentConsoleFontEx)
DEFINE_FUNC2(GetCurrentDirectoryA)
DEFINE_FUNC2(GetCurrentDirectoryW)
DEFINE_FUNC0(GetCurrentProcess)
DEFINE_FUNC0(GetCurrentProcessId)
DEFINE_FUNC0(GetCurrentProcessorNumber)
DEFINE_FUNC0(GetCurrentThread)
DEFINE_FUNC0(GetCurrentThreadId)
DEFINE_FUNC6(GetDateFormatA)
DEFINE_FUNC7(GetDateFormatEx)
DEFINE_FUNC6(GetDateFormatW)
DEFINE_FUNC3(GetDefaultCommConfigA)
DEFINE_FUNC3(GetDefaultCommConfigW)
DEFINE_FUNC2(GetDevicePowerState)
DEFINE_FUNC5(GetDiskFreeSpaceA)
DEFINE_FUNC4(GetDiskFreeSpaceExA)
DEFINE_FUNC4(GetDiskFreeSpaceExW)
DEFINE_FUNC5(GetDiskFreeSpaceW)
DEFINE_FUNC2(GetDllDirectoryA)
DEFINE_FUNC2(GetDllDirectoryW)
DEFINE_FUNC1(GetDriveTypeA)
DEFINE_FUNC1(GetDriveTypeW)
DEFINE_FUNC8(GetDurationFormat)
DEFINE_FUNC8(GetDurationFormatEx)
DEFINE_FUNC1(GetDynamicTimeZoneInformation)
DEFINE_FUNC0(GetEnvironmentStrings)
DEFINE_FUNC0(GetEnvironmentStringsA)
DEFINE_FUNC0(GetEnvironmentStringsW)
DEFINE_FUNC3(GetEnvironmentVariableA)
DEFINE_FUNC3(GetEnvironmentVariableW)
DEFINE_FUNC0(GetErrorMode)
DEFINE_FUNC2(GetExitCodeProcess)
DEFINE_FUNC2(GetExitCodeThread)
DEFINE_FUNC1(GetFileAttributesA)
DEFINE_FUNC3(GetFileAttributesExA)
DEFINE_FUNC3(GetFileAttributesExW)
DEFINE_FUNC4(GetFileAttributesTransactedA)
DEFINE_FUNC4(GetFileAttributesTransactedW)
DEFINE_FUNC1(GetFileAttributesW)
DEFINE_FUNC6(GetFileBandwidthReservation)
DEFINE_FUNC2(GetFileInformationByHandle)
DEFINE_FUNC4(GetFileInformationByHandleEx)
DEFINE_FUNC4(GetFileMUIInfo)
DEFINE_FUNC7(GetFileMUIPath)
DEFINE_FUNC2(GetFileSize)
DEFINE_FUNC2(GetFileSizeEx)
DEFINE_FUNC4(GetFileTime)
DEFINE_FUNC1(GetFileType)
DEFINE_FUNC4(GetFinalPathNameByHandleA)
DEFINE_FUNC4(GetFinalPathNameByHandleW)
DEFINE_FUNC4(GetFirmwareEnvironmentVariableA)
DEFINE_FUNC4(GetFirmwareEnvironmentVariableW)
DEFINE_FUNC4(GetFullPathNameA)
DEFINE_FUNC5(GetFullPathNameTransactedA)
DEFINE_FUNC5(GetFullPathNameTransactedW)
DEFINE_FUNC4(GetFullPathNameW)
DEFINE_FUNC5(GetGeoInfoA)
DEFINE_FUNC5(GetGeoInfoW)
DEFINE_FUNC2(GetHandleInformation)
DEFINE_FUNC0(GetLargePageMinimum)
DEFINE_FUNC1(GetLargestConsoleWindowSize)
DEFINE_FUNC0(GetLastError)
DEFINE_FUNC1(GetLocalTime)
DEFINE_FUNC4(GetLocaleInfoA)
DEFINE_FUNC4(GetLocaleInfoEx)
DEFINE_FUNC4(GetLocaleInfoW)
DEFINE_FUNC2(GetLogicalDriveStringsA)
DEFINE_FUNC2(GetLogicalDriveStringsW)
DEFINE_FUNC0(GetLogicalDrives)
DEFINE_FUNC2(GetLogicalProcessorInformation)
DEFINE_FUNC3(GetLongPathNameA)
DEFINE_FUNC4(GetLongPathNameTransactedA)
DEFINE_FUNC4(GetLongPathNameTransactedW)
DEFINE_FUNC3(GetLongPathNameW)
DEFINE_FUNC5(GetMailslotInfo)
DEFINE_FUNC3(GetModuleFileNameA)
DEFINE_FUNC3(GetModuleFileNameW)
DEFINE_FUNC1(GetModuleHandleA)
DEFINE_FUNC3(GetModuleHandleExA)
DEFINE_FUNC3(GetModuleHandleExW)
DEFINE_FUNC1(GetModuleHandleW)
DEFINE_FUNC3(GetNLSVersion)
DEFINE_FUNC3(GetNLSVersionEx)
DEFINE_FUNC5(GetNamedPipeAttribute)
DEFINE_FUNC3(GetNamedPipeClientComputerNameA)
DEFINE_FUNC3(GetNamedPipeClientComputerNameW)
DEFINE_FUNC2(GetNamedPipeClientProcessId)
DEFINE_FUNC2(GetNamedPipeClientSessionId)
DEFINE_FUNC7(GetNamedPipeHandleStateA)
DEFINE_FUNC7(GetNamedPipeHandleStateW)
DEFINE_FUNC5(GetNamedPipeInfo)
DEFINE_FUNC2(GetNamedPipeServerProcessId)
DEFINE_FUNC2(GetNamedPipeServerSessionId)
DEFINE_FUNC1(GetNativeSystemInfo)
DEFINE_FUNC2(GetNumaAvailableMemoryNode)
DEFINE_FUNC1(GetNumaHighestNodeNumber)
DEFINE_FUNC2(GetNumaNodeProcessorMask)
DEFINE_FUNC2(GetNumaProcessorNode)
DEFINE_FUNC2(GetNumaProximityNode)
DEFINE_FUNC6(GetNumberFormatA)
DEFINE_FUNC6(GetNumberFormatEx)
DEFINE_FUNC6(GetNumberFormatW)
DEFINE_FUNC2(GetNumberOfConsoleInputEvents)
DEFINE_FUNC1(GetNumberOfConsoleMouseButtons)
DEFINE_FUNC0(GetOEMCP)
DEFINE_FUNC4(GetOverlappedResult)
DEFINE_FUNC1(GetPriorityClass)
DEFINE_FUNC4(GetPrivateProfileIntA)
DEFINE_FUNC4(GetPrivateProfileIntW)
DEFINE_FUNC4(GetPrivateProfileSectionA)
DEFINE_FUNC3(GetPrivateProfileSectionNamesA)
DEFINE_FUNC3(GetPrivateProfileSectionNamesW)
DEFINE_FUNC4(GetPrivateProfileSectionW)
DEFINE_FUNC6(GetPrivateProfileStringA)
DEFINE_FUNC6(GetPrivateProfileStringW)
DEFINE_FUNC5(GetPrivateProfileStructA)
DEFINE_FUNC5(GetPrivateProfileStructW)
DEFINE_FUNC2(GetProcAddress)
DEFINE_FUNC3(GetProcessAffinityMask)
DEFINE_FUNC2(GetProcessHandleCount)
DEFINE_FUNC0(GetProcessHeap)
DEFINE_FUNC2(GetProcessHeaps)
DEFINE_FUNC1(GetProcessId)
DEFINE_FUNC1(GetProcessIdOfThread)
DEFINE_FUNC2(GetProcessIoCounters)
DEFINE_FUNC2(GetProcessPriorityBoost)
DEFINE_FUNC2(GetProcessShutdownParameters)
DEFINE_FUNC5(GetProcessTimes)
DEFINE_FUNC1(GetProcessVersion)
DEFINE_FUNC3(GetProcessWorkingSetSize)
DEFINE_FUNC4(GetProcessWorkingSetSizeEx)
DEFINE_FUNC5(GetProductInfo)
DEFINE_FUNC3(GetProfileIntA)
DEFINE_FUNC3(GetProfileIntW)
DEFINE_FUNC3(GetProfileSectionA)
DEFINE_FUNC3(GetProfileSectionW)
DEFINE_FUNC5(GetProfileStringA)
DEFINE_FUNC5(GetProfileStringW)
DEFINE_FUNC5(GetQueuedCompletionStatus)
DEFINE_FUNC6(GetQueuedCompletionStatusEx)
DEFINE_FUNC3(GetShortPathNameA)
DEFINE_FUNC3(GetShortPathNameW)
DEFINE_FUNC1(GetStartupInfoA)
DEFINE_FUNC1(GetStartupInfoW)
DEFINE_FUNC1(GetStdHandle)
DEFINE_FUNC5(GetStringScripts)
DEFINE_FUNC5(GetStringTypeA)
DEFINE_FUNC5(GetStringTypeExA)
DEFINE_FUNC5(GetStringTypeExW)
DEFINE_FUNC4(GetStringTypeW)
DEFINE_FUNC0(GetSystemDefaultLCID)
DEFINE_FUNC0(GetSystemDefaultLangID)
DEFINE_FUNC0(GetSystemDefaultUILanguage)
DEFINE_FUNC2(GetSystemDefaultLocaleName)
DEFINE_FUNC2(GetSystemDirectoryA)
DEFINE_FUNC2(GetSystemDirectoryW)
DEFINE_FUNC3(GetSystemFileCacheSize)
DEFINE_FUNC4(GetSystemFirmwareTable)
DEFINE_FUNC1(GetSystemInfo)
DEFINE_FUNC1(GetSystemPowerStatus)
DEFINE_FUNC4(GetSystemPreferredUILanguages)
DEFINE_FUNC2(GetSystemRegistryQuota)
DEFINE_FUNC1(GetSystemTime)
DEFINE_FUNC3(GetSystemTimeAdjustment)
DEFINE_FUNC1(GetSystemTimeAsFileTime)
DEFINE_FUNC3(GetSystemTimes)
DEFINE_FUNC2(GetSystemWindowsDirectoryA)
DEFINE_FUNC2(GetSystemWindowsDirectoryW)
DEFINE_FUNC2(GetSystemWow64DirectoryA)
DEFINE_FUNC2(GetSystemWow64DirectoryW)
DEFINE_FUNC4(GetTapeParameters)
DEFINE_FUNC5(GetTapePosition)
DEFINE_FUNC1(GetTapeStatus)
DEFINE_FUNC4(GetTempFileNameA)
DEFINE_FUNC4(GetTempFileNameW)
DEFINE_FUNC2(GetTempPathA)
DEFINE_FUNC2(GetTempPathW)
DEFINE_FUNC2(GetThreadContext)
DEFINE_FUNC2(GetThreadIOPendingFlag)
DEFINE_FUNC1(GetThreadId)
DEFINE_FUNC0(GetThreadLocale)
DEFINE_FUNC4(GetThreadPreferredUILanguages)
DEFINE_FUNC1(GetThreadPriority)
DEFINE_FUNC2(GetThreadPriorityBoost)
DEFINE_FUNC3(GetThreadSelectorEntry)
DEFINE_FUNC5(GetThreadTimes)
DEFINE_FUNC0(GetThreadUILanguage)
DEFINE_FUNC0(GetTickCount64)
DEFINE_FUNC0(GetTickCount)
DEFINE_FUNC6(GetTimeFormatA)
DEFINE_FUNC6(GetTimeFormatEx)
DEFINE_FUNC6(GetTimeFormatW)
DEFINE_FUNC1(GetTimeZoneInformation)
DEFINE_FUNC5(GetUILanguageInfo)
DEFINE_FUNC0(GetUserDefaultLCID)
DEFINE_FUNC0(GetUserDefaultLangID)
DEFINE_FUNC0(GetUserDefaultUILanguage)
DEFINE_FUNC2(GetUserDefaultLocaleName)
DEFINE_FUNC1(GetUserGeoID)
DEFINE_FUNC4(GetUserPreferredUILanguages)
DEFINE_FUNC0(GetVersion)
DEFINE_FUNC1(GetVersionExA)
DEFINE_FUNC1(GetVersionExW)
DEFINE_FUNC8(GetVolumeInformationA)
DEFINE_FUNC8(GetVolumeInformationByHandleW)
DEFINE_FUNC8(GetVolumeInformationW)
DEFINE_FUNC3(GetVolumeNameForVolumeMountPointA)
DEFINE_FUNC3(GetVolumeNameForVolumeMountPointW)
DEFINE_FUNC3(GetVolumePathNameA)
DEFINE_FUNC3(GetVolumePathNameW)
DEFINE_FUNC4(GetVolumePathNamesForVolumeNameA)
DEFINE_FUNC4(GetVolumePathNamesForVolumeNameW)
DEFINE_FUNC2(GetWindowsDirectoryA)
DEFINE_FUNC2(GetWindowsDirectoryW)
DEFINE_FUNC6(GetWriteWatch)
DEFINE_FUNC1(GlobalAddAtomA)
DEFINE_FUNC1(GlobalAddAtomW)
DEFINE_FUNC2(GlobalAlloc)
DEFINE_FUNC1(GlobalCompact)
DEFINE_FUNC1(GlobalDeleteAtom)
DEFINE_FUNC1(GlobalFindAtomA)
DEFINE_FUNC1(GlobalFindAtomW)
DEFINE_FUNC1(GlobalFix)
DEFINE_FUNC1(GlobalFlags)
DEFINE_FUNC1(GlobalFree)
DEFINE_FUNC3(GlobalGetAtomNameA)
DEFINE_FUNC3(GlobalGetAtomNameW)
DEFINE_FUNC1(GlobalHandle)
DEFINE_FUNC1(GlobalLock)
DEFINE_FUNC1(GlobalMemoryStatus)
DEFINE_FUNC1(GlobalMemoryStatusEx)
DEFINE_FUNC3(GlobalReAlloc)
DEFINE_FUNC1(GlobalSize)
DEFINE_FUNC1(GlobalUnWire)
DEFINE_FUNC1(GlobalUnfix)
DEFINE_FUNC1(GlobalUnlock)
DEFINE_FUNC1(GlobalWire)
DEFINE_FUNC3(Heap32First)
DEFINE_FUNC2(Heap32ListFirst)
DEFINE_FUNC2(Heap32ListNext)
DEFINE_FUNC1(Heap32Next)
DEFINE_FUNC3(HeapAlloc)
DEFINE_FUNC2(HeapCompact)
DEFINE_FUNC3(HeapCreate)
DEFINE_FUNC1(HeapDestroy)
DEFINE_FUNC3(HeapFree)
DEFINE_FUNC1(HeapLock)
DEFINE_FUNC5(HeapQueryInformation)
DEFINE_FUNC4(HeapReAlloc)
DEFINE_FUNC4(HeapSetInformation)
DEFINE_FUNC3(HeapSize)
DEFINE_FUNC1(HeapUnlock)
DEFINE_FUNC3(HeapValidate)
DEFINE_FUNC2(HeapWalk)
DEFINE_FUNC5(IdnToAscii)
DEFINE_FUNC5(IdnToUnicode)
DEFINE_FUNC1(InitAtomTable)
DEFINE_FUNC4(InitOnceBeginInitialize)
DEFINE_FUNC3(InitOnceComplete)
DEFINE_FUNC4(InitOnceExecuteOnce)
DEFINE_FUNC1(InitOnceInitialize)
DEFINE_FUNC1(InitializeConditionVariable)
DEFINE_FUNC1(InitializeCriticalSection)
DEFINE_FUNC2(InitializeCriticalSectionAndSpinCount)
DEFINE_FUNC3(InitializeCriticalSectionEx)
DEFINE_FUNC4(InitializeProcThreadAttributeList)
DEFINE_FUNC1(InitializeSListHead)
DEFINE_FUNC1(InitializeSRWLock)
DEFINE_FUNC5(InterlockedCompareExchange64)
DEFINE_FUNC3(InterlockedCompareExchange)
DEFINE_FUNC1(InterlockedDecrement)
DEFINE_FUNC2(InterlockedExchange)
DEFINE_FUNC2(InterlockedExchangeAdd)
DEFINE_FUNC1(InterlockedFlushSList)
DEFINE_FUNC1(InterlockedIncrement)
DEFINE_FUNC1(InterlockedPopEntrySList)
DEFINE_FUNC2(InterlockedPushEntrySList)
DEFINE_FUNC1(IsBadCodePtr)
DEFINE_FUNC2(IsBadHugeReadPtr)
DEFINE_FUNC2(IsBadHugeWritePtr)
DEFINE_FUNC2(IsBadReadPtr)
DEFINE_FUNC2(IsBadStringPtrA)
DEFINE_FUNC2(IsBadStringPtrW)
DEFINE_FUNC2(IsBadWritePtr)
DEFINE_FUNC1(IsDBCSLeadByte)
DEFINE_FUNC2(IsDBCSLeadByteEx)
DEFINE_FUNC0(IsDebuggerPresent)
DEFINE_FUNC5(IsNLSDefinedString)
DEFINE_FUNC3(IsProcessInJob)
DEFINE_FUNC1(IsProcessorFeaturePresent)
DEFINE_FUNC0(IsSystemResumeAutomatic)
DEFINE_FUNC0(IsThreadAFiber)
DEFINE_FUNC1(IsThreadpoolTimerSet)
DEFINE_FUNC1(IsValidCodePage)
DEFINE_FUNC2(IsValidLanguageGroup)
DEFINE_FUNC2(IsValidLocale)
DEFINE_FUNC1(IsValidLocaleName)
DEFINE_FUNC2(IsWow64Process)
DEFINE_FUNC4(LCIDToLocaleName)
DEFINE_FUNC6(LCMapStringA)
DEFINE_FUNC9(LCMapStringEx)
DEFINE_FUNC6(LCMapStringW)
DEFINE_FUNC1(LeaveCriticalSection)
DEFINE_FUNC2(LeaveCriticalSectionWhenCallbackReturns)
DEFINE_FUNC1(LoadLibraryA)
DEFINE_FUNC3(LoadLibraryExA)
DEFINE_FUNC3(LoadLibraryExW)
DEFINE_FUNC1(LoadLibraryW)
DEFINE_FUNC2(LoadModule)
DEFINE_FUNC2(LoadResource)
DEFINE_FUNC5(LoadStringBaseExW)
DEFINE_FUNC4(LoadStringBaseW)
DEFINE_FUNC2(LocalAlloc)
DEFINE_FUNC1(LocalCompact)
DEFINE_FUNC2(LocalFileTimeToFileTime)
DEFINE_FUNC1(LocalFlags)
DEFINE_FUNC1(LocalFree)
DEFINE_FUNC1(LocalHandle)
DEFINE_FUNC1(LocalLock)
DEFINE_FUNC3(LocalReAlloc)
DEFINE_FUNC2(LocalShrink)
DEFINE_FUNC1(LocalSize)
DEFINE_FUNC1(LocalUnlock)
DEFINE_FUNC2(LocaleNameToLCID)
DEFINE_FUNC5(LockFile)
DEFINE_FUNC6(LockFileEx)
DEFINE_FUNC1(LockResource)
DEFINE_FUNC3(MapUserPhysicalPages)
DEFINE_FUNC3(MapUserPhysicalPagesScatter)
DEFINE_FUNC5(MapViewOfFile)
DEFINE_FUNC6(MapViewOfFileEx)
DEFINE_FUNC7(MapViewOfFileExNuma)
DEFINE_FUNC2(Module32First)
DEFINE_FUNC2(Module32FirstW)
DEFINE_FUNC2(Module32Next)
DEFINE_FUNC2(Module32NextW)
DEFINE_FUNC2(MoveFileA)
DEFINE_FUNC3(MoveFileExA)
DEFINE_FUNC3(MoveFileExW)
DEFINE_FUNC6(MoveFileTransactedA)
DEFINE_FUNC6(MoveFileTransactedW)
DEFINE_FUNC2(MoveFileW)
DEFINE_FUNC5(MoveFileWithProgressA)
DEFINE_FUNC5(MoveFileWithProgressW)
DEFINE_FUNC3(MulDiv)
DEFINE_FUNC6(MultiByteToWideChar)
DEFINE_FUNC1(NeedCurrentDirectoryForExePathA)
DEFINE_FUNC1(NeedCurrentDirectoryForExePathW)
DEFINE_FUNC5(NotifyUILanguageChange)
DEFINE_FUNC3(OpenEventA)
DEFINE_FUNC3(OpenEventW)
DEFINE_FUNC3(OpenFile)
DEFINE_FUNC6(OpenFileById)
DEFINE_FUNC3(OpenFileMappingA)
DEFINE_FUNC3(OpenFileMappingW)
DEFINE_FUNC3(OpenJobObjectA)
DEFINE_FUNC3(OpenJobObjectW)
DEFINE_FUNC3(OpenMutexA)
DEFINE_FUNC3(OpenMutexW)
DEFINE_FUNC2(OpenPrivateNamespaceA)
DEFINE_FUNC2(OpenPrivateNamespaceW)
DEFINE_FUNC3(OpenProcess)
DEFINE_FUNC3(OpenSemaphoreA)
DEFINE_FUNC3(OpenSemaphoreW)
DEFINE_FUNC3(OpenThread)
DEFINE_FUNC3(OpenWaitableTimerA)
DEFINE_FUNC3(OpenWaitableTimerW)
DEFINE_FUNC1(OutputDebugStringA)
DEFINE_FUNC1(OutputDebugStringW)
DEFINE_FUNC4(PeekConsoleInputA)
DEFINE_FUNC4(PeekConsoleInputW)
DEFINE_FUNC6(PeekNamedPipe)
DEFINE_FUNC4(PostQueuedCompletionStatus)
DEFINE_FUNC3(PrepareTape)
DEFINE_FUNC2(Process32First)
DEFINE_FUNC2(Process32FirstW)
DEFINE_FUNC2(Process32Next)
DEFINE_FUNC2(Process32NextW)
DEFINE_FUNC2(ProcessIdToSessionId)
DEFINE_FUNC1(PulseEvent)
DEFINE_FUNC2(PurgeComm)
DEFINE_FUNC7(QueryActCtxSettingsW)
DEFINE_FUNC7(QueryActCtxW)
DEFINE_FUNC1(QueryDepthSList)
DEFINE_FUNC3(QueryDosDeviceA)
DEFINE_FUNC3(QueryDosDeviceW)
DEFINE_FUNC4(QueryFullProcessImageNameA)
DEFINE_FUNC4(QueryFullProcessImageNameW)
DEFINE_FUNC2(QueryIdleProcessorCycleTime)
DEFINE_FUNC5(QueryInformationJobObject)
DEFINE_FUNC2(QueryMemoryResourceNotification)
DEFINE_FUNC1(QueryPerformanceCounter)
DEFINE_FUNC1(QueryPerformanceFrequency)
DEFINE_FUNC2(QueryProcessCycleTime)
DEFINE_FUNC2(QueryThreadCycleTime)
DEFINE_FUNC3(QueueUserAPC)
DEFINE_FUNC3(QueueUserWorkItem)
DEFINE_FUNC4(ReOpenFile)
DEFINE_FUNC5(ReadConsoleA)
DEFINE_FUNC4(ReadConsoleInputA)
DEFINE_FUNC4(ReadConsoleInputW)
DEFINE_FUNC5(ReadConsoleOutputA)
DEFINE_FUNC5(ReadConsoleOutputAttribute)
DEFINE_FUNC5(ReadConsoleOutputCharacterA)
DEFINE_FUNC5(ReadConsoleOutputCharacterW)
DEFINE_FUNC5(ReadConsoleOutputW)
DEFINE_FUNC5(ReadConsoleW)
DEFINE_FUNC8(ReadDirectoryChangesW)
DEFINE_FUNC5(ReadFile)
DEFINE_FUNC5(ReadFileEx)
DEFINE_FUNC5(ReadFileScatter)
DEFINE_FUNC5(ReadProcessMemory)
DEFINE_FUNC2(RegDeleteTreeA)
DEFINE_FUNC2(RegDeleteTreeW)
DEFINE_FUNC0(RegDisablePredefinedCacheEx)
DEFINE_FUNC7(RegGetValueA)
DEFINE_FUNC7(RegGetValueW)
DEFINE_FUNC7(RegLoadMUIStringA)
DEFINE_FUNC7(RegLoadMUIStringW)
DEFINE_FUNC4(RegSaveKeyExA)
DEFINE_FUNC4(RegSaveKeyExW)
DEFINE_FUNC4(RegisterApplicationRecoveryCallback)
DEFINE_FUNC2(RegisterApplicationRestart)
DEFINE_FUNC6(RegisterWaitForSingleObject)
DEFINE_FUNC5(RegisterWaitForSingleObjectEx)
DEFINE_FUNC1(ReleaseActCtx)
DEFINE_FUNC1(ReleaseMutex)
DEFINE_FUNC2(ReleaseMutexWhenCallbackReturns)
DEFINE_FUNC1(ReleaseSRWLockExclusive)
DEFINE_FUNC1(ReleaseSRWLockShared)
DEFINE_FUNC3(ReleaseSemaphore)
DEFINE_FUNC3(ReleaseSemaphoreWhenCallbackReturns)
DEFINE_FUNC1(RemoveDirectoryA)
DEFINE_FUNC2(RemoveDirectoryTransactedA)
DEFINE_FUNC2(RemoveDirectoryTransactedW)
DEFINE_FUNC1(RemoveDirectoryW)
DEFINE_FUNC2(RemoveLocalAlternateComputerNameA)
DEFINE_FUNC2(RemoveLocalAlternateComputerNameW)
DEFINE_FUNC1(RemoveVectoredContinueHandler)
DEFINE_FUNC1(RemoveVectoredExceptionHandler)
DEFINE_FUNC6(ReplaceFile)
DEFINE_FUNC6(ReplaceFileA)
DEFINE_FUNC6(ReplaceFileW)
DEFINE_FUNC1(RequestDeviceWakeup)
DEFINE_FUNC1(RequestWakeupLatency)
DEFINE_FUNC1(ResetEvent)
DEFINE_FUNC2(ResetWriteWatch)
DEFINE_FUNC1(RestoreLastError)
DEFINE_FUNC1(ResumeThread)
DEFINE_FUNC1(RtlCaptureContext)
DEFINE_FUNC5(ScrollConsoleScreenBufferA)
DEFINE_FUNC5(ScrollConsoleScreenBufferW)
DEFINE_FUNC6(SearchPathA)
DEFINE_FUNC6(SearchPathW)
DEFINE_FUNC4(SetCalendarInfoA)
DEFINE_FUNC4(SetCalendarInfoW)
DEFINE_FUNC1(SetCommBreak)
DEFINE_FUNC3(SetCommConfig)
DEFINE_FUNC2(SetCommMask)
DEFINE_FUNC2(SetCommState)
DEFINE_FUNC2(SetCommTimeouts)
DEFINE_FUNC1(SetComputerNameA)
DEFINE_FUNC2(SetComputerNameExA)
DEFINE_FUNC2(SetComputerNameExW)
DEFINE_FUNC1(SetComputerNameW)
DEFINE_FUNC1(SetConsoleActiveScreenBuffer)
DEFINE_FUNC1(SetConsoleCP)
DEFINE_FUNC2(SetConsoleCtrlHandler)
DEFINE_FUNC2(SetConsoleCursor)
DEFINE_FUNC2(SetConsoleCursorInfo)
DEFINE_FUNC2(SetConsoleCursorPosition)
DEFINE_FUNC3(SetConsoleDisplayMode)
DEFINE_FUNC1(SetConsoleHistoryInfo)
DEFINE_FUNC2(SetConsoleMode)
DEFINE_FUNC1(SetConsoleOutputCP)
DEFINE_FUNC2(SetConsoleScreenBufferInfoEx)
DEFINE_FUNC2(SetConsoleScreenBufferSize)
DEFINE_FUNC2(SetConsoleTextAttribute)
DEFINE_FUNC1(SetConsoleTitleA)
DEFINE_FUNC1(SetConsoleTitleW)
DEFINE_FUNC3(SetConsoleWindowInfo)
DEFINE_FUNC2(SetCriticalSectionSpinCount)
DEFINE_FUNC3(SetCurrentConsoleFontEx)
DEFINE_FUNC1(SetCurrentDirectoryA)
DEFINE_FUNC1(SetCurrentDirectoryW)
DEFINE_FUNC3(SetDefaultCommConfigA)
DEFINE_FUNC3(SetDefaultCommConfigW)
DEFINE_FUNC1(SetDllDirectoryA)
DEFINE_FUNC1(SetDllDirectoryW)
DEFINE_FUNC1(SetDynamicTimeZoneInformation)
DEFINE_FUNC1(SetEndOfFile)
DEFINE_FUNC1(SetEnvironmentStringsA)
DEFINE_FUNC1(SetEnvironmentStringsW)
DEFINE_FUNC2(SetEnvironmentVariableA)
DEFINE_FUNC2(SetEnvironmentVariableW)
DEFINE_FUNC1(SetErrorMode)
DEFINE_FUNC1(SetEvent)
DEFINE_FUNC2(SetEventWhenCallbackReturns)
DEFINE_FUNC0(SetFileApisToANSI)
DEFINE_FUNC0(SetFileApisToOEM)
DEFINE_FUNC2(SetFileAttributesA)
DEFINE_FUNC3(SetFileAttributesTransactedA)
DEFINE_FUNC3(SetFileAttributesTransactedW)
DEFINE_FUNC2(SetFileAttributesW)
DEFINE_FUNC6(SetFileBandwidthReservation)
DEFINE_FUNC2(SetFileCompletionNotificationModes)
DEFINE_FUNC4(SetFileInformationByHandle)
DEFINE_FUNC3(SetFileIoOverlappedRange)
DEFINE_FUNC4(SetFilePointer)
DEFINE_FUNC5(SetFilePointerEx)
DEFINE_FUNC2(SetFileShortNameA)
DEFINE_FUNC2(SetFileShortNameW)
DEFINE_FUNC4(SetFileTime)
DEFINE_FUNC3(SetFileValidData)
DEFINE_FUNC4(SetFirmwareEnvironmentVariableA)
DEFINE_FUNC4(SetFirmwareEnvironmentVariableW)
DEFINE_FUNC1(SetHandleCount)
DEFINE_FUNC3(SetHandleInformation)
DEFINE_FUNC4(SetInformationJobObject)
DEFINE_FUNC1(SetLastError)
DEFINE_FUNC2(SetLocalPrimaryComputerNameA)
DEFINE_FUNC2(SetLocalPrimaryComputerNameW)
DEFINE_FUNC1(SetLocalTime)
DEFINE_FUNC3(SetLocaleInfoA)
DEFINE_FUNC3(SetLocaleInfoW)
DEFINE_FUNC2(SetMailslotInfo)
DEFINE_FUNC2(SetMessageWaitingIndicator)
DEFINE_FUNC5(SetNamedPipeAttribute)
DEFINE_FUNC4(SetNamedPipeHandleState)
DEFINE_FUNC2(SetPriorityClass)
DEFINE_FUNC2(SetProcessAffinityMask)
DEFINE_FUNC2(SetProcessPriorityBoost)
DEFINE_FUNC2(SetProcessShutdownParameters)
DEFINE_FUNC3(SetProcessWorkingSetSize)
DEFINE_FUNC4(SetProcessWorkingSetSizeEx)
DEFINE_FUNC2(SetStdHandle)
DEFINE_FUNC3(SetStdHandleEx)
DEFINE_FUNC3(SetSystemFileCacheSize)
DEFINE_FUNC2(SetSystemPowerState)
DEFINE_FUNC1(SetSystemTime)
DEFINE_FUNC2(SetSystemTimeAdjustment)
DEFINE_FUNC3(SetTapeParameters)
DEFINE_FUNC6(SetTapePosition)
DEFINE_FUNC2(SetThreadAffinityMask)
DEFINE_FUNC2(SetThreadContext)
DEFINE_FUNC1(SetThreadExecutionState)
DEFINE_FUNC2(SetThreadIdealProcessor)
DEFINE_FUNC1(SetThreadLocale)
DEFINE_FUNC3(SetThreadPreferredUILanguages)
DEFINE_FUNC2(SetThreadPriority)
DEFINE_FUNC2(SetThreadPriorityBoost)
DEFINE_FUNC1(SetThreadStackGuarantee)
DEFINE_FUNC1(SetThreadUILanguage)
DEFINE_FUNC2(SetThreadpoolThreadMaximum)
DEFINE_FUNC2(SetThreadpoolThreadMinimum)
DEFINE_FUNC4(SetThreadpoolTimer)
DEFINE_FUNC3(SetThreadpoolWait)
DEFINE_FUNC1(SetTimeZoneInformation)
DEFINE_FUNC6(SetTimerQueueTimer)
DEFINE_FUNC1(SetUnhandledExceptionFilter)
DEFINE_FUNC1(SetUserGeoID)
DEFINE_FUNC2(SetVolumeLabelA)
DEFINE_FUNC2(SetVolumeLabelW)
DEFINE_FUNC2(SetVolumeMountPointA)
DEFINE_FUNC2(SetVolumeMountPointW)
DEFINE_FUNC6(SetWaitableTimer)
DEFINE_FUNC3(SetupComm)
DEFINE_FUNC4(SignalObjectAndWait)
DEFINE_FUNC2(SizeofResource)
DEFINE_FUNC1(Sleep)
DEFINE_FUNC3(SleepConditionVariableCS)
DEFINE_FUNC4(SleepConditionVariableSRW)
DEFINE_FUNC2(SleepEx)
DEFINE_FUNC1(StartThreadpoolIo)
DEFINE_FUNC1(SubmitThreadpoolWork)
DEFINE_FUNC1(SuspendThread)
DEFINE_FUNC1(SwitchToFiber)
DEFINE_FUNC0(SwitchToThread)
DEFINE_FUNC2(SystemTimeToFileTime)
DEFINE_FUNC3(SystemTimeToTzSpecificLocalTime)
DEFINE_FUNC2(TerminateJobObject)
DEFINE_FUNC2(TerminateProcess)
DEFINE_FUNC2(TerminateThread)
DEFINE_FUNC2(Thread32First)
DEFINE_FUNC2(Thread32Next)
DEFINE_FUNC0(TlsAlloc)
DEFINE_FUNC1(TlsFree)
DEFINE_FUNC1(TlsGetValue)
DEFINE_FUNC2(TlsSetValue)
DEFINE_FUNC5(Toolhelp32ReadProcessMemory)
DEFINE_FUNC7(TransactNamedPipe)
DEFINE_FUNC2(TransmitCommChar)
DEFINE_FUNC1(TryEnterCriticalSection)
DEFINE_FUNC3(TrySubmitThreadpoolCallback)
DEFINE_FUNC3(TzSpecificLocalTimeToSystemTime)
DEFINE_FUNC1(UnhandledExceptionFilter)
DEFINE_FUNC5(UnlockFile)
DEFINE_FUNC5(UnlockFileEx)
DEFINE_FUNC1(UnmapViewOfFile)
DEFINE_FUNC0(UnregisterApplicationRecoveryCallback)
DEFINE_FUNC0(UnregisterApplicationRestart)
DEFINE_FUNC1(UnregisterWait)
DEFINE_FUNC2(UnregisterWaitEx)
DEFINE_FUNC7(UpdateProcThreadAttribute)
DEFINE_FUNC6(UpdateResourceA)
DEFINE_FUNC6(UpdateResourceW)
DEFINE_FUNC3(VerLanguageNameA)
DEFINE_FUNC3(VerLanguageNameW)
DEFINE_FUNC4(VerSetConditionMask)
DEFINE_FUNC5(VerifyScripts)
DEFINE_FUNC4(VerifyVersionInfoA)
DEFINE_FUNC4(VerifyVersionInfoW)
DEFINE_FUNC4(VirtualAlloc)
DEFINE_FUNC5(VirtualAllocEx)
DEFINE_FUNC6(VirtualAllocExNuma)
DEFINE_FUNC3(VirtualFree)
DEFINE_FUNC4(VirtualFreeEx)
DEFINE_FUNC2(VirtualLock)
DEFINE_FUNC4(VirtualProtect)
DEFINE_FUNC5(VirtualProtectEx)
DEFINE_FUNC3(VirtualQuery)
DEFINE_FUNC4(VirtualQueryEx)
DEFINE_FUNC2(VirtualUnlock)
DEFINE_FUNC0(WTSGetActiveConsoleSessionId)
DEFINE_FUNC3(WaitCommEvent)
DEFINE_FUNC2(WaitForDebugEvent)
DEFINE_FUNC4(WaitForMultipleObjects)
DEFINE_FUNC5(WaitForMultipleObjectsEx)
DEFINE_FUNC2(WaitForSingleObject)
DEFINE_FUNC3(WaitForSingleObjectEx)
DEFINE_FUNC2(WaitForThreadpoolIoCallbacks)
DEFINE_FUNC2(WaitForThreadpoolTimerCallbacks)
DEFINE_FUNC2(WaitForThreadpoolWaitCallbacks)
DEFINE_FUNC2(WaitForThreadpoolWorkCallbacks)
DEFINE_FUNC2(WaitNamedPipeA)
DEFINE_FUNC2(WaitNamedPipeW)
DEFINE_FUNC1(WakeAllConditionVariable)
DEFINE_FUNC1(WakeConditionVariable)
DEFINE_FUNC2(WerGetFlags)
DEFINE_FUNC3(WerRegisterFile)
DEFINE_FUNC2(WerRegisterMemoryBlock)
DEFINE_FUNC1(WerSetFlags)
DEFINE_FUNC1(WerUnregisterFile)
DEFINE_FUNC1(WerUnregisterMemoryBlock)
DEFINE_FUNC1(WerpInitiateRemoteRecovery)
DEFINE_FUNC8(WideCharToMultiByte)
DEFINE_FUNC2(WinExec)
DEFINE_FUNC1(Wow64DisableWow64FsRedirection)
DEFINE_FUNC1(Wow64EnableWow64FsRedirection)
DEFINE_FUNC2(Wow64GetThreadContext)
DEFINE_FUNC1(Wow64RevertWow64FsRedirection)
DEFINE_FUNC2(Wow64SetThreadContext)
DEFINE_FUNC1(Wow64SuspendThread)
DEFINE_FUNC5(WriteConsoleA)
DEFINE_FUNC4(WriteConsoleInputA)
DEFINE_FUNC4(WriteConsoleInputW)
DEFINE_FUNC5(WriteConsoleOutputA)
DEFINE_FUNC5(WriteConsoleOutputAttribute)
DEFINE_FUNC5(WriteConsoleOutputCharacterA)
DEFINE_FUNC5(WriteConsoleOutputCharacterW)
DEFINE_FUNC5(WriteConsoleOutputW)
DEFINE_FUNC5(WriteConsoleW)
DEFINE_FUNC5(WriteFile)
DEFINE_FUNC5(WriteFileEx)
DEFINE_FUNC5(WriteFileGather)
DEFINE_FUNC3(WritePrivateProfileSectionA)
DEFINE_FUNC3(WritePrivateProfileSectionW)
DEFINE_FUNC4(WritePrivateProfileStringA)
DEFINE_FUNC4(WritePrivateProfileStringW)
DEFINE_FUNC5(WritePrivateProfileStructA)
DEFINE_FUNC5(WritePrivateProfileStructW)
DEFINE_FUNC5(WriteProcessMemory)
DEFINE_FUNC2(WriteProfileSectionA)
DEFINE_FUNC2(WriteProfileSectionW)
DEFINE_FUNC3(WriteProfileStringA)
DEFINE_FUNC3(WriteProfileStringW)
DEFINE_FUNC4(WriteTapemark)
DEFINE_FUNC1(ZombifyActCtx)
DEFINE_FUNC3(_hread)
DEFINE_FUNC3(_hwrite)
DEFINE_FUNC1(_lclose)
DEFINE_FUNC2(_lcreat)
DEFINE_FUNC3(_llseek)
DEFINE_FUNC2(_lopen)
DEFINE_FUNC3(_lread)
DEFINE_FUNC3(_lwrite)
DEFINE_FUNC2(lstrcat)
DEFINE_FUNC2(lstrcatA)
DEFINE_FUNC2(lstrcatW)
DEFINE_FUNC2(lstrcmp)
DEFINE_FUNC2(lstrcmpA)
DEFINE_FUNC2(lstrcmpW)
DEFINE_FUNC2(lstrcmpi)
DEFINE_FUNC2(lstrcmpiA)
DEFINE_FUNC2(lstrcmpiW)
DEFINE_FUNC2(lstrcpy)
DEFINE_FUNC2(lstrcpyA)
DEFINE_FUNC2(lstrcpyW)
DEFINE_FUNC3(lstrcpyn)
DEFINE_FUNC3(lstrcpynA)
DEFINE_FUNC3(lstrcpynW)
DEFINE_FUNC1(lstrlen)
DEFINE_FUNC1(lstrlenA)
DEFINE_FUNC1(lstrlenW)
DEFINE_FUNC2(CopyLZFile)
DEFINE_FUNC2(GetExpandedNameA)
DEFINE_FUNC2(GetExpandedNameW)
DEFINE_FUNC1(LZClose)
DEFINE_FUNC2(LZCopy)
DEFINE_FUNC0(LZDone)
DEFINE_FUNC1(LZInit)
DEFINE_FUNC3(LZOpenFileA)
DEFINE_FUNC3(LZOpenFileW)
DEFINE_FUNC3(LZRead)
DEFINE_FUNC3(LZSeek)
DEFINE_FUNC0(LZStart)
