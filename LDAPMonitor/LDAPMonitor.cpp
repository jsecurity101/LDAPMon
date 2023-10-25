#include <ws2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <evntrace.h>
#include <Evntcons.h>
#include <psapi.h>
#include <sstream>
#include <vector>
#include <tdh.h>
#include "LDAPMon.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "tdh.lib")

static GUID LDAP = { 0x099614a5, 0x5dd7, 0x4788, { 0x8b, 0xc9, 0xe2, 0x9f, 0x43, 0xdb, 0x28, 0xfc } };

NTSTATUS WriteETWEvents(PEVENT_DATA_DESCRIPTOR eventData, EVENT_DESCRIPTOR eventDescriptor, int metaDataSize) {
    REGHANDLE RegistrationHandle = NULL;
    NTSTATUS status = EventRegister(
        &LDAPMonProvider,
        NULL,
        NULL,
        &RegistrationHandle
    );
    if (status != ERROR_SUCCESS)
    {
        return status;
    }
    status = EventWrite(
        RegistrationHandle,
        &eventDescriptor,
        metaDataSize,
        eventData
    );
    if (status != ERROR_SUCCESS)
    {
        EventUnregister(RegistrationHandle);
        return status;
    }

    //
    //CleanUp
    //
    EventUnregister(RegistrationHandle);
}

NTSTATUS LdapSearch(PEVENT_RECORD EventRecord) {
    DWORD status = ERROR_SUCCESS;
    PTRACE_EVENT_INFO pInfo = NULL;
    DWORD bufferSize = 0;
    UINT32 scopeOfSearch = 0;
    WCHAR* searchFilter = NULL;
    WCHAR* distinguishedName = NULL;
    WCHAR* attributeList = NULL;
    ULONG processId = 0;

    //
    // Determine the required buffer size for the event info.
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    if (ERROR_INSUFFICIENT_BUFFER == status) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (pInfo == NULL) {
            goto Exit;
        }

        // Get the event info
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }

    if (ERROR_SUCCESS != status) {
        goto Exit;
    }

    //
    // Iterate through all the top-level properties
    //
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        DWORD propertySize = 0;

        WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.PropertyName = (ULONGLONG)propertyName;
        dataDescriptor.ArrayIndex = ULONG_MAX;

        status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting size of property\n");
            goto Exit;
        }

        BYTE* propertyData = (BYTE*)malloc(propertySize);
        if (!propertyData) {
            OutputDebugString(L"Error allocating memory for property\n");
            goto Exit;
        }

        status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting property\n");
            goto Exit;
        }

        //
        // Going to use a switch statement to determine which property we are dealing with
        //
        switch (i) {
        case 0:
        {
            ULONG value = *(ULONG*)propertyData;
            scopeOfSearch = value;
            break;
        }
        case 1:
        {
            searchFilter = (WCHAR*)malloc(static_cast<size_t>(propertySize + 1));
            if (!searchFilter) {
				OutputDebugString(L"Error allocating memory for property - SearchFilter\n");
				goto Exit;
			}
			wcscpy_s(searchFilter, propertySize, (WCHAR*)propertyData);
            break;
        }
        case 2:
        {
            distinguishedName = (WCHAR*)malloc(static_cast<size_t>(propertySize + 1));
            if (!distinguishedName) {
				OutputDebugString(L"Error allocating memory for property - DistinguishedName\n");
				goto Exit;
			}
			wcscpy_s(distinguishedName, propertySize, (WCHAR*)propertyData);
			break;
        }
        case 3: 
        {
            attributeList = (WCHAR*)malloc(static_cast<size_t>(propertySize + 1));
            if (!attributeList) {
				OutputDebugString(L"Error allocating memory for property - AttributeList\n");
				goto Exit;
			}
			wcscpy_s(attributeList, propertySize, (WCHAR*)propertyData);
			break;
        }
        case 4: 
        {
            processId = *(ULONG*)propertyData;
			break;
        }
        }

        free(propertyData);
    }

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    EVENT_DATA_DESCRIPTOR EventData[6];
    EventDataDescCreate(&EventData[0], &ft, sizeof(ft));
    EventDataDescCreate(&EventData[1], &scopeOfSearch, sizeof(scopeOfSearch));
    EventDataDescCreate(&EventData[2], searchFilter, (wcslen(searchFilter) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[3], distinguishedName, (wcslen(distinguishedName) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[4], attributeList, (wcslen(attributeList) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[5], &processId, sizeof(processId));

    status = WriteETWEvents(EventData, LDAPSearch, 6);
    if (status != ERROR_SUCCESS) {
		OutputDebugString(L"Error writing ETW event\n");
        goto Exit;
	}

Exit:
    {
        if (searchFilter != NULL)
        {
            free(searchFilter);
        }
        if (distinguishedName != NULL)
        {
            free(distinguishedName);
        }
        if (attributeList != NULL)
        {
            free(attributeList);
        }
        if (pInfo != NULL) {
            free(pInfo);
        }
        return status;
    }
}

void ProcessEvent(PEVENT_RECORD EventRecord) {
    NTSTATUS status;
    PEVENT_HEADER eventHeader = &EventRecord->EventHeader;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;
    if (eventHeader->ProviderId == LDAP) 
    {
        switch (eventDescriptor->Id) {
        case 30: 
        {
            status = LdapSearch(EventRecord);

            break;
        }
        default: {
            break;
        }
        }
 
    }
}

DWORD UninstallManifest() {

    printf("[*] Uninstalling Manifest....\n");
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe um LDAPMon.man";
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess Failed");
        return GetLastError();
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[*] Manifest Uninstalled....\n");

    return 0;
}

DWORD InstallManifest() {
    printf("[*] Installing Manifest....\n");
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe im LDAPMon.man";
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess Failed");
        return GetLastError();
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[*] Manifest Installed....\n");

    return 0;
}

int main()
{
    UninstallManifest();
    CopyFile(L"LDAPMon.dll", L"C:\\Windows\\LDAPMon.dll", FALSE);
    printf("[*] LDAPMon.dll Copied to C:\\Windows\\LDAPMon.dll\n");
    InstallManifest();

    printf("[*] Starting LDAPMon...\n");
    const char name[] = "LDAPMon";
    TRACEHANDLE hTrace = 0;
    ULONG result, bufferSize;
    EVENT_TRACE_LOGFILEA trace;
    EVENT_TRACE_PROPERTIES* traceProp;

    memset(&trace, 0, sizeof(EVENT_TRACE_LOGFILEA));
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.LoggerName = (LPSTR)name;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEvent;

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(name) + sizeof(WCHAR);

    traceProp = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.ClientContext = 2;
    traceProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    traceProp->LogFileNameOffset = 0;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    if ((result = StartTraceA(&hTrace, (LPCSTR)name, traceProp)) != ERROR_SUCCESS) {
        printf("[!] Error StartTraceA\n");
        printf("[!] Error code: %d\n", result);
        return 2;
    }

    if ((result = EnableTraceEx(
        &LDAP,
        nullptr,
        hTrace,
        TRUE,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        printf("[!] Error EnableTraceEx\n");
    }
    printf("[+] LDAP Trace Enabled\n");

    hTrace = OpenTraceA(&trace);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        printf("[!] Error OpenTrace\n");
        return 3;
    }

    result = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error ProcessTrace\n");
        return 4;
    }
}

