#include "dllstub_def.h"

static const char DLL_NAME[]="ntdll.nt.dll";

DEFINE_FUNC2(CsrAllocateCaptureBuffer)
DEFINE_FUNC3(CsrAllocateMessagePointer)
DEFINE_FUNC4(CsrCaptureMessageBuffer)
DEFINE_FUNC5(CsrCaptureMessageString)
DEFINE_FUNC2(CsrCaptureTimeout)
DEFINE_FUNC4(CsrClientCallServer)
DEFINE_FUNC1(CsrFreeCaptureBuffer)
DEFINE_FUNC0(CsrIdentifyAlertableThread)
DEFINE_FUNC0(CsrNewThread)
DEFINE_FUNC3(CsrProbeForRead)
DEFINE_FUNC3(CsrProbeForWrite)
DEFINE_FUNC2(CsrSetPriorityClass)
DEFINE_FUNC0(DbgBreakPoint)
DEFINE_FUNC_(DbgPrint)
DEFINE_FUNC_(DbgPrintReturnControlC)
DEFINE_FUNC3(DbgPrompt)
DEFINE_FUNC0(DbgUiConnectToDbg)
DEFINE_FUNC2(DbgUiContinue)
DEFINE_FUNC2(DbgUiWaitStateChange)
DEFINE_FUNC0(DbgUserBreakPoint)
DEFINE_FUNC0(KiRaiseUserExceptionDispatcher)
DEFINE_FUNC5(KiUserApcDispatcher)
DEFINE_FUNC3(KiUserCallbackDispatcher)
DEFINE_FUNC2(KiUserExceptionDispatcher)
DEFINE_FUNC4(LdrAccessResource)
DEFINE_FUNC0(LdrAlternateResourcesEnabled)
DEFINE_FUNC1(LdrDisableThreadCalloutsForDll)
DEFINE_FUNC5(LdrEnumResources)
DEFINE_FUNC2(LdrFindEntryForAddress)
DEFINE_FUNC4(LdrFindResourceDirectory_U)
DEFINE_FUNC4(LdrFindResource_U)
DEFINE_FUNC0(LdrFlushAlternateResourceModules)
DEFINE_FUNC4(LdrGetDllHandle)
DEFINE_FUNC4(LdrGetProcedureAddress)
DEFINE_FUNC4(LdrInitializeThunk)
DEFINE_FUNC2(LdrLoadAlternateResourceModule)
DEFINE_FUNC4(LdrLoadDll)
DEFINE_FUNC4(LdrProcessRelocationBlock)
DEFINE_FUNC6(LdrQueryImageFileExecutionOptions)
DEFINE_FUNC3(LdrQueryProcessModuleInformation)
DEFINE_FUNC0(LdrShutdownProcess)
DEFINE_FUNC0(LdrShutdownThread)
DEFINE_FUNC1(LdrUnloadAlternateResourceModule)
DEFINE_FUNC1(LdrUnloadDll)
DEFINE_FUNC4(LdrVerifyImageMatchesChecksum)
DEFINE_FUNC6(NtAcceptConnectPort)
DEFINE_FUNC8(NtAccessCheck)
DEFINE_FUNC11(NtAccessCheckAndAuditAlarm)
DEFINE_FUNC11(NtAccessCheckByType)
DEFINE_FUNC16(NtAccessCheckByTypeAndAuditAlarm)
DEFINE_FUNC11(NtAccessCheckByTypeResultList)
DEFINE_FUNC16(NtAccessCheckByTypeResultListAndAuditAlarm)
DEFINE_FUNC17(NtAccessCheckByTypeResultListAndAuditAlarmByHandle)
DEFINE_FUNC3(NtAddAtom)
DEFINE_FUNC6(NtAdjustGroupsToken)
DEFINE_FUNC6(NtAdjustPrivilegesToken)
DEFINE_FUNC2(NtAlertResumeThread)
DEFINE_FUNC1(NtAlertThread)
DEFINE_FUNC1(NtAllocateLocallyUniqueId)
DEFINE_FUNC3(NtAllocateUserPhysicalPages)
DEFINE_FUNC4(NtAllocateUuids)
DEFINE_FUNC6(NtAllocateVirtualMemory)
DEFINE_FUNC2(NtAreMappedFilesTheSame)
DEFINE_FUNC2(NtAssignProcessToJobObject)
DEFINE_FUNC3(NtCallbackReturn)
DEFINE_FUNC1(NtCancelDeviceWakeupRequest)
DEFINE_FUNC2(NtCancelIoFile)
DEFINE_FUNC2(NtCancelTimer)
DEFINE_FUNC1(NtClearEvent)
DEFINE_FUNC1(NtClose)
DEFINE_FUNC3(NtCloseObjectAuditAlarm)
DEFINE_FUNC1(NtCompleteConnectPort)
DEFINE_FUNC8(NtConnectPort)
DEFINE_FUNC2(NtContinue)
DEFINE_FUNC3(NtCreateDirectoryObject)
DEFINE_FUNC5(NtCreateEvent)
DEFINE_FUNC3(NtCreateEventPair)
DEFINE_FUNC11(NtCreateFile)
DEFINE_FUNC4(NtCreateIoCompletion)
DEFINE_FUNC3(NtCreateJobObject)
DEFINE_FUNC7(NtCreateKey)
DEFINE_FUNC8(NtCreateMailslotFile)
DEFINE_FUNC4(NtCreateMutant)
DEFINE_FUNC14(NtCreateNamedPipeFile)
DEFINE_FUNC4(NtCreatePagingFile)
DEFINE_FUNC5(NtCreatePort)
DEFINE_FUNC8(NtCreateProcess)
DEFINE_FUNC9(NtCreateProfile)
DEFINE_FUNC7(NtCreateSection)
DEFINE_FUNC5(NtCreateSemaphore)
DEFINE_FUNC4(NtCreateSymbolicLinkObject)
DEFINE_FUNC8(NtCreateThread)
DEFINE_FUNC4(NtCreateTimer)
DEFINE_FUNC13(NtCreateToken)
DEFINE_FUNC5(NtCreateWaitablePort)
DEFINE_FUNC2(NtDelayExecution)
DEFINE_FUNC1(NtDeleteAtom)
DEFINE_FUNC1(NtDeleteFile)
DEFINE_FUNC1(NtDeleteKey)
DEFINE_FUNC3(NtDeleteObjectAuditAlarm)
DEFINE_FUNC2(NtDeleteValueKey)
DEFINE_FUNC10(NtDeviceIoControlFile)
DEFINE_FUNC1(NtDisplayString)
DEFINE_FUNC7(NtDuplicateObject)
DEFINE_FUNC6(NtDuplicateToken)
DEFINE_FUNC6(NtEnumerateKey)
DEFINE_FUNC6(NtEnumerateValueKey)
DEFINE_FUNC2(NtExtendSection)
DEFINE_FUNC6(NtFilterToken)
DEFINE_FUNC3(NtFindAtom)
DEFINE_FUNC2(NtFlushBuffersFile)
DEFINE_FUNC3(NtFlushInstructionCache)
DEFINE_FUNC1(NtFlushKey)
DEFINE_FUNC4(NtFlushVirtualMemory)
DEFINE_FUNC0(NtFlushWriteBuffer)
DEFINE_FUNC3(NtFreeUserPhysicalPages)
DEFINE_FUNC4(NtFreeVirtualMemory)
DEFINE_FUNC10(NtFsControlFile)
DEFINE_FUNC2(NtGetContextThread)
DEFINE_FUNC2(NtGetDevicePowerState)
DEFINE_FUNC4(NtGetPlugPlayEvent)
DEFINE_FUNC7(NtGetWriteWatch)
DEFINE_FUNC2(NtImpersonateClientOfPort)
DEFINE_FUNC3(NtImpersonateThread)
DEFINE_FUNC1(NtInitializeRegistry)
DEFINE_FUNC4(NtInitiatePowerAction)
DEFINE_FUNC0(NtIsSystemResumeAutomatic)
DEFINE_FUNC2(NtListenPort)
DEFINE_FUNC1(NtLoadDriver)
DEFINE_FUNC2(NtLoadKey)
DEFINE_FUNC3(NtLoadKey2)
DEFINE_FUNC10(NtLockFile)
DEFINE_FUNC4(NtLockVirtualMemory)
DEFINE_FUNC1(NtMakeTemporaryObject)
DEFINE_FUNC3(NtMapUserPhysicalPages)
DEFINE_FUNC3(NtMapUserPhysicalPagesScatter)
DEFINE_FUNC10(NtMapViewOfSection)
DEFINE_FUNC9(NtNotifyChangeDirectoryFile)
DEFINE_FUNC10(NtNotifyChangeKey)
DEFINE_FUNC12(NtNotifyChangeMultipleKeys)
DEFINE_FUNC3(NtOpenDirectoryObject)
DEFINE_FUNC3(NtOpenEvent)
DEFINE_FUNC3(NtOpenEventPair)
DEFINE_FUNC6(NtOpenFile)
DEFINE_FUNC3(NtOpenIoCompletion)
DEFINE_FUNC3(NtOpenJobObject)
DEFINE_FUNC3(NtOpenKey)
DEFINE_FUNC3(NtOpenMutant)
DEFINE_FUNC12(NtOpenObjectAuditAlarm)
DEFINE_FUNC4(NtOpenProcess)
DEFINE_FUNC3(NtOpenProcessToken)
DEFINE_FUNC3(NtOpenSection)
DEFINE_FUNC3(NtOpenSemaphore)
DEFINE_FUNC3(NtOpenSymbolicLinkObject)
DEFINE_FUNC4(NtOpenThread)
DEFINE_FUNC4(NtOpenThreadToken)
DEFINE_FUNC3(NtOpenTimer)
DEFINE_FUNC3(NtPlugPlayControl)
DEFINE_FUNC5(NtPowerInformation)
DEFINE_FUNC3(NtPrivilegeCheck)
DEFINE_FUNC5(NtPrivilegedServiceAuditAlarm)
DEFINE_FUNC6(NtPrivilegeObjectAuditAlarm)
DEFINE_FUNC5(NtProtectVirtualMemory)
DEFINE_FUNC2(NtPulseEvent)
DEFINE_FUNC2(NtQueryAttributesFile)
DEFINE_FUNC2(NtQueryDefaultLocale)
DEFINE_FUNC1(NtQueryDefaultUILanguage)
DEFINE_FUNC11(NtQueryDirectoryFile)
DEFINE_FUNC7(NtQueryDirectoryObject)
DEFINE_FUNC9(NtQueryEaFile)
DEFINE_FUNC5(NtQueryEvent)
DEFINE_FUNC2(NtQueryFullAttributesFile)
DEFINE_FUNC5(NtQueryInformationAtom)
DEFINE_FUNC5(NtQueryInformationFile)
DEFINE_FUNC5(NtQueryInformationJobObject)
DEFINE_FUNC5(NtQueryInformationPort)
DEFINE_FUNC5(NtQueryInformationProcess)
DEFINE_FUNC5(NtQueryInformationThread)
DEFINE_FUNC5(NtQueryInformationToken)
DEFINE_FUNC1(NtQueryInstallUILanguage)
DEFINE_FUNC2(NtQueryIntervalProfile)
DEFINE_FUNC5(NtQueryIoCompletion)
DEFINE_FUNC5(NtQueryKey)
DEFINE_FUNC6(NtQueryMultipleValueKey)
DEFINE_FUNC5(NtQueryMutant)
DEFINE_FUNC5(NtQueryObject)
DEFINE_FUNC2(NtQueryOpenSubKeys)
DEFINE_FUNC2(NtQueryPerformanceCounter)
DEFINE_FUNC9(NtQueryQuotaInformationFile)
DEFINE_FUNC5(NtQuerySection)
DEFINE_FUNC5(NtQuerySecurityObject)
DEFINE_FUNC5(NtQuerySemaphore)
DEFINE_FUNC3(NtQuerySymbolicLinkObject)
DEFINE_FUNC4(NtQuerySystemEnvironmentValue)
DEFINE_FUNC4(NtQuerySystemInformation)
DEFINE_FUNC1(NtQuerySystemTime)
DEFINE_FUNC5(NtQueryTimer)
DEFINE_FUNC3(NtQueryTimerResolution)
DEFINE_FUNC6(NtQueryValueKey)
DEFINE_FUNC6(NtQueryVirtualMemory)
DEFINE_FUNC5(NtQueryVolumeInformationFile)
DEFINE_FUNC5(NtQueueApcThread)
DEFINE_FUNC3(NtRaiseException)
DEFINE_FUNC6(NtRaiseHardError)
DEFINE_FUNC9(NtReadFile)
DEFINE_FUNC9(NtReadFileScatter)
DEFINE_FUNC6(NtReadRequestData)
DEFINE_FUNC5(NtReadVirtualMemory)
DEFINE_FUNC1(NtRegisterThreadTerminatePort)
DEFINE_FUNC2(NtReleaseMutant)
DEFINE_FUNC3(NtReleaseSemaphore)
DEFINE_FUNC5(NtRemoveIoCompletion)
DEFINE_FUNC3(NtReplaceKey)
DEFINE_FUNC2(NtReplyPort)
DEFINE_FUNC4(NtReplyWaitReceivePort)
DEFINE_FUNC5(NtReplyWaitReceivePortEx)
DEFINE_FUNC2(NtReplyWaitReplyPort)
DEFINE_FUNC1(NtRequestDeviceWakeup)
DEFINE_FUNC2(NtRequestPort)
DEFINE_FUNC3(NtRequestWaitReplyPort)
DEFINE_FUNC1(NtRequestWakeupLatency)
DEFINE_FUNC2(NtResetEvent)
DEFINE_FUNC3(NtResetWriteWatch)
DEFINE_FUNC3(NtRestoreKey)
DEFINE_FUNC2(NtResumeThread)
DEFINE_FUNC2(NtSaveKey)
DEFINE_FUNC3(NtSaveMergedKeys)
DEFINE_FUNC9(NtSecureConnectPort)
DEFINE_FUNC2(NtSetContextThread)
DEFINE_FUNC1(NtSetDefaultHardErrorPort)
DEFINE_FUNC2(NtSetDefaultLocale)
DEFINE_FUNC1(NtSetDefaultUILanguage)
DEFINE_FUNC4(NtSetEaFile)
DEFINE_FUNC2(NtSetEvent)
DEFINE_FUNC1(NtSetHighEventPair)
DEFINE_FUNC1(NtSetHighWaitLowEventPair)
DEFINE_FUNC5(NtSetInformationFile)
DEFINE_FUNC4(NtSetInformationJobObject)
DEFINE_FUNC4(NtSetInformationKey)
DEFINE_FUNC4(NtSetInformationObject)
DEFINE_FUNC4(NtSetInformationProcess)
DEFINE_FUNC4(NtSetInformationThread)
DEFINE_FUNC4(NtSetInformationToken)
DEFINE_FUNC2(NtSetIntervalProfile)
DEFINE_FUNC5(NtSetIoCompletion)
DEFINE_FUNC1(NtSetLowEventPair)
DEFINE_FUNC1(NtSetLowWaitHighEventPair)
DEFINE_FUNC4(NtSetQuotaInformationFile)
DEFINE_FUNC3(NtSetSecurityObject)
DEFINE_FUNC2(NtSetSystemEnvironmentValue)
DEFINE_FUNC3(NtSetSystemInformation)
DEFINE_FUNC3(NtSetSystemPowerState)
DEFINE_FUNC2(NtSetSystemTime)
DEFINE_FUNC2(NtSetThreadExecutionState)
DEFINE_FUNC7(NtSetTimer)
DEFINE_FUNC3(NtSetTimerResolution)
DEFINE_FUNC1(NtSetUuidSeed)
DEFINE_FUNC6(NtSetValueKey)
DEFINE_FUNC5(NtSetVolumeInformationFile)
DEFINE_FUNC1(NtShutdownSystem)
DEFINE_FUNC4(NtSignalAndWaitForSingleObject)
DEFINE_FUNC1(NtStartProfile)
DEFINE_FUNC1(NtStopProfile)
DEFINE_FUNC2(NtSuspendThread)
DEFINE_FUNC6(NtSystemDebugControl)
DEFINE_FUNC2(NtTerminateJobObject)
DEFINE_FUNC2(NtTerminateProcess)
DEFINE_FUNC2(NtTerminateThread)
DEFINE_FUNC0(NtTestAlert)
DEFINE_FUNC1(NtUnloadDriver)
DEFINE_FUNC1(NtUnloadKey)
DEFINE_FUNC5(NtUnlockFile)
DEFINE_FUNC4(NtUnlockVirtualMemory)
DEFINE_FUNC2(NtUnmapViewOfSection)
DEFINE_FUNC2(NtVdmControl)
DEFINE_FUNC5(NtWaitForMultipleObjects)
DEFINE_FUNC3(NtWaitForSingleObject)
DEFINE_FUNC1(NtWaitHighEventPair)
DEFINE_FUNC1(NtWaitLowEventPair)
DEFINE_FUNC9(NtWriteFile)
DEFINE_FUNC9(NtWriteFileGather)
DEFINE_FUNC6(NtWriteRequestData)
DEFINE_FUNC5(NtWriteVirtualMemory)
DEFINE_FUNC0(NtYieldExecution)
DEFINE_FUNC1(RtlAbortRXact)
DEFINE_FUNC3(RtlAbsoluteToSelfRelativeSD)
DEFINE_FUNC0(RtlAcquirePebLock)
DEFINE_FUNC2(RtlAcquireResourceExclusive)
DEFINE_FUNC2(RtlAcquireResourceShared)
DEFINE_FUNC4(RtlAddAccessAllowedAce)
DEFINE_FUNC5(RtlAddAccessAllowedAceEx)
DEFINE_FUNC7(RtlAddAccessAllowedObjectAce)
DEFINE_FUNC4(RtlAddAccessDeniedAce)
DEFINE_FUNC5(RtlAddAccessDeniedAceEx)
DEFINE_FUNC7(RtlAddAccessDeniedObjectAce)
DEFINE_FUNC5(RtlAddAce)
DEFINE_FUNC6(RtlAddActionToRXact)
DEFINE_FUNC3(RtlAddAtomToAtomTable)
DEFINE_FUNC8(RtlAddAttributeActionToRXact)
DEFINE_FUNC6(RtlAddAuditAccessAce)
DEFINE_FUNC7(RtlAddAuditAccessAceEx)
DEFINE_FUNC9(RtlAddAuditAccessObjectAce)
DEFINE_FUNC6(RtlAddCompoundAce)
DEFINE_FUNC9(RtlAddRange)
DEFINE_FUNC4(RtlAdjustPrivilege)
DEFINE_FUNC11(RtlAllocateAndInitializeSid)
DEFINE_FUNC2(RtlAllocateHandle)
DEFINE_FUNC3(RtlAllocateHeap)
DEFINE_FUNC1(RtlAnsiCharToUnicodeChar)
DEFINE_FUNC1(RtlAnsiStringToUnicodeSize)
DEFINE_FUNC3(RtlAnsiStringToUnicodeString)
DEFINE_FUNC2(RtlAppendAsciizToString)
DEFINE_FUNC2(RtlAppendStringToString)
DEFINE_FUNC2(RtlAppendUnicodeStringToString)
DEFINE_FUNC2(RtlAppendUnicodeToString)
DEFINE_FUNC1(RtlApplyRXact)
DEFINE_FUNC1(RtlApplyRXactNoFlush)
DEFINE_FUNC2(RtlAreAllAccessesGranted)
DEFINE_FUNC2(RtlAreAnyAccessesGranted)
DEFINE_FUNC3(RtlAreBitsClear)
DEFINE_FUNC3(RtlAreBitsSet)
DEFINE_FUNC4(RtlAssert)
DEFINE_FUNC2(RtlCancelTimer)
DEFINE_FUNC4(RtlCaptureStackBackTrace)
DEFINE_FUNC3(RtlCharToInteger)
DEFINE_FUNC1(RtlCheckForOrphanedCriticalSections)
DEFINE_FUNC2(RtlCheckRegistryKey)
DEFINE_FUNC1(RtlClearAllBits)
DEFINE_FUNC3(RtlClearBits)
DEFINE_FUNC2(RtlCompactHeap)
DEFINE_FUNC3(RtlCompareMemory)
DEFINE_FUNC3(RtlCompareMemoryUlong)
DEFINE_FUNC3(RtlCompareString)
DEFINE_FUNC3(RtlCompareUnicodeString)
DEFINE_FUNC8(RtlCompressBuffer)
DEFINE_FUNC6(RtlConsoleMultiByteToUnicodeN)
DEFINE_FUNC1(RtlConvertExclusiveToShared)
DEFINE_FUNC1(RtlConvertSharedToExclusive)
DEFINE_FUNC3(RtlConvertSidToUnicodeString)
DEFINE_FUNC6(RtlConvertToAutoInheritSecurityObject)
DEFINE_FUNC3(RtlConvertUiListToApiList)
DEFINE_FUNC1(RtlConvertUlongToLargeInteger)
DEFINE_FUNC2(RtlCopyLuid)
DEFINE_FUNC3(RtlCopyLuidAndAttributesArray)
DEFINE_FUNC2(RtlCopyRangeList)
DEFINE_FUNC2(RtlCopySecurityDescriptor)
DEFINE_FUNC3(RtlCopySid)
DEFINE_FUNC7(RtlCopySidAndAttributesArray)
DEFINE_FUNC2(RtlCopyString)
DEFINE_FUNC2(RtlCopyUnicodeString)
DEFINE_FUNC3(RtlCreateAcl)
DEFINE_FUNC5(RtlCreateAndSetSD)
DEFINE_FUNC2(RtlCreateAtomTable)
DEFINE_FUNC2(RtlCreateEnvironment)
DEFINE_FUNC6(RtlCreateHeap)
DEFINE_FUNC10(RtlCreateProcessParameters)
DEFINE_FUNC2(RtlCreateQueryDebugBuffer)
DEFINE_FUNC2(RtlCreateRegistryKey)
DEFINE_FUNC2(RtlCreateSecurityDescriptor)
DEFINE_FUNC4(RtlCreateTagHeap)
DEFINE_FUNC7(RtlCreateTimer)
DEFINE_FUNC1(RtlCreateTimerQueue)
DEFINE_FUNC2(RtlCreateUnicodeString)
DEFINE_FUNC2(RtlCreateUnicodeStringFromAsciiz)
DEFINE_FUNC10(RtlCreateUserProcess)
DEFINE_FUNC10(RtlCreateUserThread)
DEFINE_FUNC6(RtlCustomCPToUnicodeN)
DEFINE_FUNC4(RtlCutoverTimeToSystemTime)
DEFINE_FUNC0(RtlDebugPrintTimes)
DEFINE_FUNC6(RtlDecompressBuffer)
DEFINE_FUNC8(RtlDecompressFragment)
DEFINE_FUNC1(RtlDefaultNpAcl)
DEFINE_FUNC1(RtlDelete)
DEFINE_FUNC2(RtlDeleteAce)
DEFINE_FUNC2(RtlDeleteAtomFromAtomTable)
DEFINE_FUNC1(RtlDeleteCriticalSection)
DEFINE_FUNC2(RtlDeleteElementGenericTable)
DEFINE_FUNC2(RtlDeleteNoSplay)
DEFINE_FUNC2(RtlDeleteOwnersRanges)
DEFINE_FUNC6(RtlDeleteRange)
DEFINE_FUNC1(RtlDeleteResource)
DEFINE_FUNC1(RtlDeleteSecurityObject)
DEFINE_FUNC3(RtlDeleteTimer)
DEFINE_FUNC1(RtlDeleteTimerQueue)
DEFINE_FUNC2(RtlDeleteTimerQueueEx)
DEFINE_FUNC1(RtlDeNormalizeProcessParams)
DEFINE_FUNC1(RtlDeregisterWait)
DEFINE_FUNC2(RtlDeregisterWaitEx)
DEFINE_FUNC1(RtlDestroyAtomTable)
DEFINE_FUNC1(RtlDestroyEnvironment)
DEFINE_FUNC1(RtlDestroyHandleTable)
DEFINE_FUNC1(RtlDestroyHeap)
DEFINE_FUNC1(RtlDestroyProcessParameters)
DEFINE_FUNC1(RtlDestroyQueryDebugBuffer)
DEFINE_FUNC1(RtlDetermineDosPathNameType_U)
DEFINE_FUNC1(RtlDoesFileExists_U)
DEFINE_FUNC4(RtlDosPathNameToNtPathName_U)
DEFINE_FUNC6(RtlDosSearchPath_U)
DEFINE_FUNC3(RtlDowncaseUnicodeString)
DEFINE_FUNC2(RtlEmptyAtomTable)
DEFINE_FUNC0(RtlEnableEarlyCriticalSectionEventCreation)
DEFINE_FUNC2(RtlEnlargedIntegerMultiply)
DEFINE_FUNC4(RtlEnlargedUnsignedDivide)
DEFINE_FUNC2(RtlEnlargedUnsignedMultiply)
DEFINE_FUNC1(RtlEnterCriticalSection)
DEFINE_FUNC2(RtlEnumerateGenericTable)
DEFINE_FUNC2(RtlEnumerateGenericTableWithoutSplaying)
DEFINE_FUNC2(RtlEnumProcessHeaps)
DEFINE_FUNC2(RtlEqualComputerName)
DEFINE_FUNC2(RtlEqualDomainName)
DEFINE_FUNC2(RtlEqualLuid)
DEFINE_FUNC2(RtlEqualPrefixSid)
DEFINE_FUNC2(RtlEqualSid)
DEFINE_FUNC3(RtlEqualString)
DEFINE_FUNC3(RtlEqualUnicodeString)
DEFINE_FUNC1(RtlEraseUnicodeString)
DEFINE_FUNC4(RtlExpandEnvironmentStrings_U)
DEFINE_FUNC4(RtlExtendedLargeIntegerDivide)
DEFINE_FUNC5(RtlExtendedMagicDivide)
DEFINE_FUNC4(RtlExtendHeap)
DEFINE_FUNC3(RtlFillMemory)
DEFINE_FUNC3(RtlFillMemoryUlong)
DEFINE_FUNC3(RtlFindClearBits)
DEFINE_FUNC3(RtlFindClearBitsAndSet)
DEFINE_FUNC2(RtlFindLeastSignificantBit)
DEFINE_FUNC2(RtlFindLongestRunClear)
DEFINE_FUNC5(RtlFindMessage)
DEFINE_FUNC2(RtlFindMostSignificantBit)
DEFINE_FUNC3(RtlFindNextForwardRunClear)
DEFINE_FUNC12(RtlFindRange)
DEFINE_FUNC3(RtlFindSetBits)
DEFINE_FUNC3(RtlFindSetBitsAndClear)
DEFINE_FUNC2(RtlFirstFreeAce)
DEFINE_FUNC1(RtlFormatCurrentUserKeyPath)
DEFINE_FUNC9(RtlFormatMessage)
DEFINE_FUNC1(RtlFreeAnsiString)
DEFINE_FUNC2(RtlFreeHandle)
DEFINE_FUNC3(RtlFreeHeap)
DEFINE_FUNC1(RtlFreeOemString)
DEFINE_FUNC1(RtlFreeSid)
DEFINE_FUNC1(RtlFreeUnicodeString)
DEFINE_FUNC2(RtlFreeUserThreadStack)
DEFINE_FUNC4(RtlGenerate8dot3Name)
DEFINE_FUNC3(RtlGetAce)
DEFINE_FUNC2(RtlGetCallersAddress)
DEFINE_FUNC3(RtlGetCompressionWorkSpaceSize)
DEFINE_FUNC3(RtlGetControlSecurityDescriptor)
DEFINE_FUNC2(RtlGetCurrentDirectory_U)
DEFINE_FUNC4(RtlGetDaclSecurityDescriptor)
DEFINE_FUNC2(RtlGetElementGenericTable)
DEFINE_FUNC3(RtlGetFirstRange)
DEFINE_FUNC4(RtlGetFullPathName_U)
DEFINE_FUNC3(RtlGetGroupSecurityDescriptor)
DEFINE_FUNC0(RtlGetLongestNtPathLength)
DEFINE_FUNC3(RtlGetNextRange)
DEFINE_FUNC0(RtlGetNtGlobalFlags)
DEFINE_FUNC1(RtlGetNtProductType)
DEFINE_FUNC3(RtlGetOwnerSecurityDescriptor)
DEFINE_FUNC2(RtlGetProcessHeaps)
DEFINE_FUNC4(RtlGetSaclSecurityDescriptor)
DEFINE_FUNC2(RtlGetSecurityDescriptorRMControl)
DEFINE_FUNC5(RtlGetUserInfoHeap)
DEFINE_FUNC1(RtlGetVersion)
DEFINE_FUNC2(RtlGUIDFromString)
DEFINE_FUNC1(RtlIdentifierAuthoritySid)
DEFINE_FUNC4(RtlImageDirectoryEntryToData)
DEFINE_FUNC1(RtlImageNtHeader)
DEFINE_FUNC3(RtlImageRvaToSection)
DEFINE_FUNC4(RtlImageRvaToVa)
DEFINE_FUNC1(RtlImpersonateSelf)
DEFINE_FUNC2(RtlInitAnsiString)
DEFINE_FUNC2(RtlInitCodePageTable)
DEFINE_FUNC4(RtlInitNlsTables)
DEFINE_FUNC2(RtlInitString)
DEFINE_FUNC2(RtlInitUnicodeString)
DEFINE_FUNC1(RtlInitializeAtomPackage)
DEFINE_FUNC3(RtlInitializeBitMap)
DEFINE_FUNC5(RtlInitializeContext)
DEFINE_FUNC1(RtlInitializeCriticalSection)
DEFINE_FUNC2(RtlInitializeCriticalSectionAndSpinCount)
DEFINE_FUNC5(RtlInitializeGenericTable)
DEFINE_FUNC3(RtlInitializeHandleTable)
DEFINE_FUNC3(RtlInitializeRXact)
DEFINE_FUNC1(RtlInitializeRangeList)
DEFINE_FUNC1(RtlInitializeResource)
DEFINE_FUNC3(RtlInitializeSid)
DEFINE_FUNC4(RtlInsertElementGenericTable)
DEFINE_FUNC4(RtlIntegerToChar)
DEFINE_FUNC3(RtlIntegerToUnicodeString)
DEFINE_FUNC2(RtlInvertRangeList)
DEFINE_FUNC1(RtlIsDosDeviceName_U)
DEFINE_FUNC3(RtlIsNameLegalDOS8Dot3)
DEFINE_FUNC10(RtlIsRangeAvailable)
DEFINE_FUNC3(RtlIsTextUnicode)
DEFINE_FUNC2(RtlIsValidHandle)
DEFINE_FUNC3(RtlIsValidIndexHandle)
DEFINE_FUNC4(RtlLargeIntegerAdd)
DEFINE_FUNC3(RtlLargeIntegerArithmeticShift)
DEFINE_FUNC5(RtlLargeIntegerDivide)
DEFINE_FUNC2(RtlLargeIntegerNegate)
DEFINE_FUNC3(RtlLargeIntegerShiftLeft)
DEFINE_FUNC3(RtlLargeIntegerShiftRight)
DEFINE_FUNC4(RtlLargeIntegerSubtract)
DEFINE_FUNC4(RtlLargeIntegerToChar)
DEFINE_FUNC1(RtlLeaveCriticalSection)
DEFINE_FUNC1(RtlLengthRequiredSid)
DEFINE_FUNC1(RtlLengthSecurityDescriptor)
DEFINE_FUNC1(RtlLengthSid)
DEFINE_FUNC2(RtlLocalTimeToSystemTime)
DEFINE_FUNC1(RtlLockHeap)
DEFINE_FUNC3(RtlLookupAtomInAtomTable)
DEFINE_FUNC2(RtlLookupElementGenericTable)
DEFINE_FUNC3(RtlMakeSelfRelativeSD)
DEFINE_FUNC2(RtlMapGenericMask)
DEFINE_FUNC4(RtlMergeRangeLists)
DEFINE_FUNC3(RtlMoveMemory)
DEFINE_FUNC5(RtlMultiByteToUnicodeN)
DEFINE_FUNC3(RtlMultiByteToUnicodeSize)
DEFINE_FUNC10(RtlNewInstanceSecurityObject)
DEFINE_FUNC6(RtlNewSecurityGrantedAccess)
DEFINE_FUNC6(RtlNewSecurityObject)
DEFINE_FUNC8(RtlNewSecurityObjectEx)
DEFINE_FUNC1(RtlNormalizeProcessParams)
DEFINE_FUNC1(RtlNtStatusToDosError)
DEFINE_FUNC1(RtlNumberGenericTableElements)
DEFINE_FUNC1(RtlNumberOfClearBits)
DEFINE_FUNC1(RtlNumberOfSetBits)
DEFINE_FUNC1(RtlOemStringToUnicodeSize)
DEFINE_FUNC3(RtlOemStringToUnicodeString)
DEFINE_FUNC2(RtlOpenCurrentUser)
DEFINE_FUNC2(RtlPcToFileHeader)
DEFINE_FUNC2(RtlPinAtomInAtomTable)
DEFINE_FUNC3(RtlPrefixString)
DEFINE_FUNC3(RtlPrefixUnicodeString)
DEFINE_FUNC2(RtlProtectHeap)
DEFINE_FUNC6(RtlQueryAtomInAtomTable)
DEFINE_FUNC3(RtlQueryEnvironmentVariable_U)
DEFINE_FUNC4(RtlQueryInformationAcl)
DEFINE_FUNC1(RtlQueryProcessBackTraceInformation)
DEFINE_FUNC3(RtlQueryProcessDebugInformation)
DEFINE_FUNC1(RtlQueryProcessHeapInformation)
DEFINE_FUNC1(RtlQueryProcessLockInformation)
DEFINE_FUNC5(RtlQueryRegistryValues)
DEFINE_FUNC5(RtlQuerySecurityObject)
DEFINE_FUNC5(RtlQueryTagHeap)
DEFINE_FUNC1(RtlQueryTimeZoneInformation)
DEFINE_FUNC3(RtlQueueWorkItem)
DEFINE_FUNC1(RtlRaiseException)
DEFINE_FUNC1(RtlRaiseStatus)
DEFINE_FUNC4(RtlReAllocateHeap)
DEFINE_FUNC1(RtlRealPredecessor)
DEFINE_FUNC6(RtlRegisterWait)
DEFINE_FUNC0(RtlReleasePebLock)
DEFINE_FUNC1(RtlReleaseResource)
DEFINE_FUNC7(RtlRemoteCall)
DEFINE_FUNC1(RtlResetRtlTranslations)
DEFINE_FUNC2(RtlRunDecodeUnicodeString)
DEFINE_FUNC2(RtlRunEncodeUnicodeString)
DEFINE_FUNC2(RtlSecondsSince1970ToTime)
DEFINE_FUNC2(RtlSecondsSince1980ToTime)
DEFINE_FUNC2(RtlSelfRelativeToAbsoluteSD2)
DEFINE_FUNC11(RtlSelfRelativeToAbsoluteSD)
DEFINE_FUNC1(RtlSetAllBits)
DEFINE_FUNC3(RtlSetAttributesSecurityDescriptor)
DEFINE_FUNC3(RtlSetBits)
DEFINE_FUNC3(RtlSetControlSecurityDescriptor)
DEFINE_FUNC2(RtlSetCriticalSectionSpinCount)
DEFINE_FUNC1(RtlSetCurrentDirectory_U)
DEFINE_FUNC2(RtlSetCurrentEnvironment)
DEFINE_FUNC4(RtlSetDaclSecurityDescriptor)
DEFINE_FUNC3(RtlSetEnvironmentVariable)
DEFINE_FUNC3(RtlSetGroupSecurityDescriptor)
DEFINE_FUNC4(RtlSetInformationAcl)
DEFINE_FUNC3(RtlSetIoCompletionCallback)
DEFINE_FUNC3(RtlSetOwnerSecurityDescriptor)
DEFINE_FUNC4(RtlSetSaclSecurityDescriptor)
DEFINE_FUNC2(RtlSetSecurityDescriptorRMControl)
DEFINE_FUNC5(RtlSetSecurityObject)
DEFINE_FUNC6(RtlSetSecurityObjectEx)
DEFINE_FUNC2(RtlSetThreadPoolStartFunc)
DEFINE_FUNC1(RtlSetTimeZoneInformation)
DEFINE_FUNC7(RtlSetTimer)
DEFINE_FUNC1(RtlSetUnicodeCallouts)
DEFINE_FUNC5(RtlSetUserFlagsHeap)
DEFINE_FUNC4(RtlSetUserValueHeap)
DEFINE_FUNC3(RtlSizeHeap)
DEFINE_FUNC1(RtlSplay)
DEFINE_FUNC1(RtlStartRXact)
DEFINE_FUNC2(RtlStringFromGUID)
DEFINE_FUNC1(RtlSubAuthorityCountSid)
DEFINE_FUNC2(RtlSubAuthoritySid)
DEFINE_FUNC1(RtlSubtreePredecessor)
DEFINE_FUNC1(RtlSubtreeSuccessor)
DEFINE_FUNC2(RtlSystemTimeToLocalTime)
DEFINE_FUNC2(RtlTimeFieldsToTime)
DEFINE_FUNC2(RtlTimeToElapsedTimeFields)
DEFINE_FUNC2(RtlTimeToSecondsSince1970)
DEFINE_FUNC2(RtlTimeToSecondsSince1980)
DEFINE_FUNC2(RtlTimeToTimeFields)
DEFINE_FUNC4(RtlTraceDatabaseAdd)
DEFINE_FUNC5(RtlTraceDatabaseCreate)
DEFINE_FUNC1(RtlTraceDatabaseDestroy)
DEFINE_FUNC3(RtlTraceDatabaseEnumerate)
DEFINE_FUNC4(RtlTraceDatabaseFind)
DEFINE_FUNC1(RtlTraceDatabaseLock)
DEFINE_FUNC1(RtlTraceDatabaseUnlock)
DEFINE_FUNC1(RtlTraceDatabaseValidate)
DEFINE_FUNC1(RtlTryEnterCriticalSection)
DEFINE_FUNC1(RtlUnicodeStringToAnsiSize)
DEFINE_FUNC3(RtlUnicodeStringToAnsiString)
DEFINE_FUNC3(RtlUnicodeStringToCountedOemString)
DEFINE_FUNC3(RtlUnicodeStringToInteger)
DEFINE_FUNC1(RtlUnicodeStringToOemSize)
DEFINE_FUNC3(RtlUnicodeStringToOemString)
DEFINE_FUNC5(RtlUnicodeToMultiByteN)
DEFINE_FUNC3(RtlUnicodeToMultiByteSize)
DEFINE_FUNC5(RtlUnicodeToOemN)
DEFINE_FUNC1(RtlUniform)
DEFINE_FUNC1(RtlUnlockHeap)
DEFINE_FUNC1(RtlUpcaseUnicodeChar)
DEFINE_FUNC3(RtlUpcaseUnicodeString)
DEFINE_FUNC3(RtlUpcaseUnicodeStringToAnsiString)
DEFINE_FUNC3(RtlUpcaseUnicodeStringToCountedOemString)
DEFINE_FUNC3(RtlUpcaseUnicodeStringToOemString)
DEFINE_FUNC6(RtlUpcaseUnicodeToCustomCPN)
DEFINE_FUNC5(RtlUpcaseUnicodeToMultiByteN)
DEFINE_FUNC5(RtlUpcaseUnicodeToOemN)
DEFINE_FUNC4(RtlUpdateTimer)
DEFINE_FUNC1(RtlUpperChar)
DEFINE_FUNC3(RtlUsageHeap)
DEFINE_FUNC1(RtlValidAcl)
DEFINE_FUNC3(RtlValidRelativeSecurityDescriptor)
DEFINE_FUNC1(RtlValidSecurityDescriptor)
DEFINE_FUNC1(RtlValidSid)
DEFINE_FUNC3(RtlValidateHeap)
DEFINE_FUNC0(RtlValidateProcessHeaps)
DEFINE_FUNC4(RtlVerifyVersionInfo)
DEFINE_FUNC3(RtlWalkFrameChain)
DEFINE_FUNC2(RtlWalkHeap)
DEFINE_FUNC6(RtlWriteRegistryValue)
DEFINE_FUNC2(RtlZeroHeap)
DEFINE_FUNC2(RtlZeroMemory)
DEFINE_FUNC6(RtlpNtCreateKey)
DEFINE_FUNC4(RtlpNtEnumerateSubKey)
DEFINE_FUNC1(RtlpNtMakeTemporaryKey)
DEFINE_FUNC4(RtlpNtOpenKey)
DEFINE_FUNC5(RtlpNtQueryValueKey)
DEFINE_FUNC4(RtlpNtSetValueKey)
DEFINE_FUNC1(RtlpUnWaitCriticalSection)
DEFINE_FUNC1(RtlpWaitForCriticalSection)
DEFINE_FUNC1(RtlxAnsiStringToUnicodeSize)
DEFINE_FUNC1(RtlxOemStringToUnicodeSize)
DEFINE_FUNC1(RtlxUnicodeStringToAnsiSize)
DEFINE_FUNC1(RtlxUnicodeStringToOemSize)
DEFINE_FUNC6(ZwAcceptConnectPort)
DEFINE_FUNC8(ZwAccessCheck)
DEFINE_FUNC11(ZwAccessCheckAndAuditAlarm)
DEFINE_FUNC11(ZwAccessCheckByType)
DEFINE_FUNC16(ZwAccessCheckByTypeAndAuditAlarm)
DEFINE_FUNC11(ZwAccessCheckByTypeResultList)
DEFINE_FUNC16(ZwAccessCheckByTypeResultListAndAuditAlarm)
DEFINE_FUNC17(ZwAccessCheckByTypeResultListAndAuditAlarmByHandle)
DEFINE_FUNC3(ZwAddAtom)
DEFINE_FUNC6(ZwAdjustGroupsToken)
DEFINE_FUNC6(ZwAdjustPrivilegesToken)
DEFINE_FUNC2(ZwAlertResumeThread)
DEFINE_FUNC1(ZwAlertThread)
DEFINE_FUNC1(ZwAllocateLocallyUniqueId)
DEFINE_FUNC3(ZwAllocateUserPhysicalPages)
DEFINE_FUNC4(ZwAllocateUuids)
DEFINE_FUNC6(ZwAllocateVirtualMemory)
DEFINE_FUNC2(ZwAreMappedFilesTheSame)
DEFINE_FUNC2(ZwAssignProcessToJobObject)
DEFINE_FUNC3(ZwCallbackReturn)
DEFINE_FUNC1(ZwCancelDeviceWakeupRequest)
DEFINE_FUNC2(ZwCancelIoFile)
DEFINE_FUNC2(ZwCancelTimer)
DEFINE_FUNC1(ZwClearEvent)
DEFINE_FUNC1(ZwClose)
DEFINE_FUNC3(ZwCloseObjectAuditAlarm)
DEFINE_FUNC1(ZwCompleteConnectPort)
DEFINE_FUNC8(ZwConnectPort)
DEFINE_FUNC2(ZwContinue)
DEFINE_FUNC3(ZwCreateDirectoryObject)
DEFINE_FUNC5(ZwCreateEvent)
DEFINE_FUNC3(ZwCreateEventPair)
DEFINE_FUNC11(ZwCreateFile)
DEFINE_FUNC4(ZwCreateIoCompletion)
DEFINE_FUNC3(ZwCreateJobObject)
DEFINE_FUNC7(ZwCreateKey)
DEFINE_FUNC8(ZwCreateMailslotFile)
DEFINE_FUNC4(ZwCreateMutant)
DEFINE_FUNC14(ZwCreateNamedPipeFile)
DEFINE_FUNC4(ZwCreatePagingFile)
DEFINE_FUNC5(ZwCreatePort)
DEFINE_FUNC8(ZwCreateProcess)
DEFINE_FUNC9(ZwCreateProfile)
DEFINE_FUNC7(ZwCreateSection)
DEFINE_FUNC5(ZwCreateSemaphore)
DEFINE_FUNC4(ZwCreateSymbolicLinkObject)
DEFINE_FUNC8(ZwCreateThread)
DEFINE_FUNC4(ZwCreateTimer)
DEFINE_FUNC13(ZwCreateToken)
DEFINE_FUNC5(ZwCreateWaitablePort)
DEFINE_FUNC2(ZwDelayExecution)
DEFINE_FUNC1(ZwDeleteAtom)
DEFINE_FUNC1(ZwDeleteFile)
DEFINE_FUNC1(ZwDeleteKey)
DEFINE_FUNC3(ZwDeleteObjectAuditAlarm)
DEFINE_FUNC2(ZwDeleteValueKey)
DEFINE_FUNC10(ZwDeviceIoControlFile)
DEFINE_FUNC1(ZwDisplayString)
DEFINE_FUNC7(ZwDuplicateObject)
DEFINE_FUNC6(ZwDuplicateToken)
DEFINE_FUNC6(ZwEnumerateKey)
DEFINE_FUNC6(ZwEnumerateValueKey)
DEFINE_FUNC2(ZwExtendSection)
DEFINE_FUNC6(ZwFilterToken)
DEFINE_FUNC3(ZwFindAtom)
DEFINE_FUNC2(ZwFlushBuffersFile)
DEFINE_FUNC3(ZwFlushInstructionCache)
DEFINE_FUNC1(ZwFlushKey)
DEFINE_FUNC4(ZwFlushVirtualMemory)
DEFINE_FUNC0(ZwFlushWriteBuffer)
DEFINE_FUNC3(ZwFreeUserPhysicalPages)
DEFINE_FUNC4(ZwFreeVirtualMemory)
DEFINE_FUNC10(ZwFsControlFile)
DEFINE_FUNC2(ZwGetContextThread)
DEFINE_FUNC2(ZwGetDevicePowerState)
DEFINE_FUNC4(ZwGetPlugPlayEvent)
DEFINE_FUNC7(ZwGetWriteWatch)
DEFINE_FUNC2(ZwImpersonateClientOfPort)
DEFINE_FUNC3(ZwImpersonateThread)
DEFINE_FUNC1(ZwInitializeRegistry)
DEFINE_FUNC4(ZwInitiatePowerAction)
DEFINE_FUNC0(ZwIsSystemResumeAutomatic)
DEFINE_FUNC2(ZwListenPort)
DEFINE_FUNC1(ZwLoadDriver)
DEFINE_FUNC2(ZwLoadKey)
DEFINE_FUNC3(ZwLoadKey2)
DEFINE_FUNC10(ZwLockFile)
DEFINE_FUNC4(ZwLockVirtualMemory)
DEFINE_FUNC1(ZwMakeTemporaryObject)
DEFINE_FUNC3(ZwMapUserPhysicalPages)
DEFINE_FUNC3(ZwMapUserPhysicalPagesScatter)
DEFINE_FUNC10(ZwMapViewOfSection)
DEFINE_FUNC9(ZwNotifyChangeDirectoryFile)
DEFINE_FUNC10(ZwNotifyChangeKey)
DEFINE_FUNC12(ZwNotifyChangeMultipleKeys)
DEFINE_FUNC3(ZwOpenDirectoryObject)
DEFINE_FUNC3(ZwOpenEvent)
DEFINE_FUNC3(ZwOpenEventPair)
DEFINE_FUNC6(ZwOpenFile)
DEFINE_FUNC3(ZwOpenIoCompletion)
DEFINE_FUNC3(ZwOpenJobObject)
DEFINE_FUNC3(ZwOpenKey)
DEFINE_FUNC3(ZwOpenMutant)
DEFINE_FUNC12(ZwOpenObjectAuditAlarm)
DEFINE_FUNC4(ZwOpenProcess)
DEFINE_FUNC3(ZwOpenProcessToken)
DEFINE_FUNC3(ZwOpenSection)
DEFINE_FUNC3(ZwOpenSemaphore)
DEFINE_FUNC3(ZwOpenSymbolicLinkObject)
DEFINE_FUNC4(ZwOpenThread)
DEFINE_FUNC4(ZwOpenThreadToken)
DEFINE_FUNC3(ZwOpenTimer)
DEFINE_FUNC3(ZwPlugPlayControl)
DEFINE_FUNC5(ZwPowerInformation)
DEFINE_FUNC3(ZwPrivilegeCheck)
DEFINE_FUNC5(ZwPrivilegedServiceAuditAlarm)
DEFINE_FUNC6(ZwPrivilegeObjectAuditAlarm)
DEFINE_FUNC5(ZwProtectVirtualMemory)
DEFINE_FUNC2(ZwPulseEvent)
DEFINE_FUNC2(ZwQueryAttributesFile)
DEFINE_FUNC2(ZwQueryDefaultLocale)
DEFINE_FUNC1(ZwQueryDefaultUILanguage)
DEFINE_FUNC11(ZwQueryDirectoryFile)
DEFINE_FUNC7(ZwQueryDirectoryObject)
DEFINE_FUNC9(ZwQueryEaFile)
DEFINE_FUNC5(ZwQueryEvent)
DEFINE_FUNC2(ZwQueryFullAttributesFile)
DEFINE_FUNC5(ZwQueryInformationAtom)
DEFINE_FUNC5(ZwQueryInformationFile)
DEFINE_FUNC5(ZwQueryInformationJobObject)
DEFINE_FUNC5(ZwQueryInformationPort)
DEFINE_FUNC5(ZwQueryInformationProcess)
DEFINE_FUNC5(ZwQueryInformationThread)
DEFINE_FUNC5(ZwQueryInformationToken)
DEFINE_FUNC1(ZwQueryInstallUILanguage)
DEFINE_FUNC2(ZwQueryIntervalProfile)
DEFINE_FUNC5(ZwQueryIoCompletion)
DEFINE_FUNC5(ZwQueryKey)
DEFINE_FUNC6(ZwQueryMultipleValueKey)
DEFINE_FUNC5(ZwQueryMutant)
DEFINE_FUNC5(ZwQueryObject)
DEFINE_FUNC2(ZwQueryOpenSubKeys)
DEFINE_FUNC2(ZwQueryPerformanceCounter)
DEFINE_FUNC9(ZwQueryQuotaInformationFile)
DEFINE_FUNC5(ZwQuerySection)
DEFINE_FUNC5(ZwQuerySecurityObject)
DEFINE_FUNC5(ZwQuerySemaphore)
DEFINE_FUNC3(ZwQuerySymbolicLinkObject)
DEFINE_FUNC4(ZwQuerySystemEnvironmentValue)
DEFINE_FUNC4(ZwQuerySystemInformation)
DEFINE_FUNC1(ZwQuerySystemTime)
DEFINE_FUNC5(ZwQueryTimer)
DEFINE_FUNC3(ZwQueryTimerResolution)
DEFINE_FUNC6(ZwQueryValueKey)
DEFINE_FUNC6(ZwQueryVirtualMemory)
DEFINE_FUNC5(ZwQueryVolumeInformationFile)
DEFINE_FUNC5(ZwQueueApcThread)
DEFINE_FUNC3(ZwRaiseException)
DEFINE_FUNC6(ZwRaiseHardError)
DEFINE_FUNC9(ZwReadFile)
DEFINE_FUNC9(ZwReadFileScatter)
DEFINE_FUNC6(ZwReadRequestData)
DEFINE_FUNC5(ZwReadVirtualMemory)
DEFINE_FUNC1(ZwRegisterThreadTerminatePort)
DEFINE_FUNC2(ZwReleaseMutant)
DEFINE_FUNC3(ZwReleaseSemaphore)
DEFINE_FUNC5(ZwRemoveIoCompletion)
DEFINE_FUNC3(ZwReplaceKey)
DEFINE_FUNC2(ZwReplyPort)
DEFINE_FUNC4(ZwReplyWaitReceivePort)
DEFINE_FUNC5(ZwReplyWaitReceivePortEx)
DEFINE_FUNC2(ZwReplyWaitReplyPort)
DEFINE_FUNC1(ZwRequestDeviceWakeup)
DEFINE_FUNC2(ZwRequestPort)
DEFINE_FUNC3(ZwRequestWaitReplyPort)
DEFINE_FUNC1(ZwRequestWakeupLatency)
DEFINE_FUNC2(ZwResetEvent)
DEFINE_FUNC3(ZwResetWriteWatch)
DEFINE_FUNC3(ZwRestoreKey)
DEFINE_FUNC2(ZwResumeThread)
DEFINE_FUNC2(ZwSaveKey)
DEFINE_FUNC3(ZwSaveMergedKeys)
DEFINE_FUNC9(ZwSecureConnectPort)
DEFINE_FUNC2(ZwSetContextThread)
DEFINE_FUNC1(ZwSetDefaultHardErrorPort)
DEFINE_FUNC2(ZwSetDefaultLocale)
DEFINE_FUNC1(ZwSetDefaultUILanguage)
DEFINE_FUNC4(ZwSetEaFile)
DEFINE_FUNC2(ZwSetEvent)
DEFINE_FUNC1(ZwSetHighEventPair)
DEFINE_FUNC1(ZwSetHighWaitLowEventPair)
DEFINE_FUNC5(ZwSetInformationFile)
DEFINE_FUNC4(ZwSetInformationJobObject)
DEFINE_FUNC4(ZwSetInformationKey)
DEFINE_FUNC4(ZwSetInformationObject)
DEFINE_FUNC4(ZwSetInformationProcess)
DEFINE_FUNC4(ZwSetInformationThread)
DEFINE_FUNC4(ZwSetInformationToken)
DEFINE_FUNC2(ZwSetIntervalProfile)
DEFINE_FUNC5(ZwSetIoCompletion)
DEFINE_FUNC1(ZwSetLowEventPair)
DEFINE_FUNC1(ZwSetLowWaitHighEventPair)
DEFINE_FUNC4(ZwSetQuotaInformationFile)
DEFINE_FUNC3(ZwSetSecurityObject)
DEFINE_FUNC2(ZwSetSystemEnvironmentValue)
DEFINE_FUNC3(ZwSetSystemInformation)
DEFINE_FUNC3(ZwSetSystemPowerState)
DEFINE_FUNC2(ZwSetSystemTime)
DEFINE_FUNC2(ZwSetThreadExecutionState)
DEFINE_FUNC7(ZwSetTimer)
DEFINE_FUNC3(ZwSetTimerResolution)
DEFINE_FUNC1(ZwSetUuidSeed)
DEFINE_FUNC6(ZwSetValueKey)
DEFINE_FUNC5(ZwSetVolumeInformationFile)
DEFINE_FUNC1(ZwShutdownSystem)
DEFINE_FUNC4(ZwSignalAndWaitForSingleObject)
DEFINE_FUNC1(ZwStartProfile)
DEFINE_FUNC1(ZwStopProfile)
DEFINE_FUNC2(ZwSuspendThread)
DEFINE_FUNC6(ZwSystemDebugControl)
DEFINE_FUNC2(ZwTerminateJobObject)
DEFINE_FUNC2(ZwTerminateProcess)
DEFINE_FUNC2(ZwTerminateThread)
DEFINE_FUNC0(ZwTestAlert)
DEFINE_FUNC1(ZwUnloadDriver)
DEFINE_FUNC1(ZwUnloadKey)
DEFINE_FUNC5(ZwUnlockFile)
DEFINE_FUNC4(ZwUnlockVirtualMemory)
DEFINE_FUNC2(ZwUnmapViewOfSection)
DEFINE_FUNC2(ZwVdmControl)
DEFINE_FUNC5(ZwWaitForMultipleObjects)
DEFINE_FUNC3(ZwWaitForSingleObject)
DEFINE_FUNC1(ZwWaitHighEventPair)
DEFINE_FUNC1(ZwWaitLowEventPair)
DEFINE_FUNC9(ZwWriteFile)
DEFINE_FUNC9(ZwWriteFileGather)
DEFINE_FUNC6(ZwWriteRequestData)
DEFINE_FUNC5(ZwWriteVirtualMemory)
DEFINE_FUNC0(ZwYieldExecution)
// manually added:
DEFINE_FUNC4(RtlUnwind)
DEFINE_FUNC5(vDbgPrintExWithPrefix)
