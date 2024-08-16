#include "ProcessFactory.h"
#include <vector>
#include <psapi.h>
#include <sstream>

// Constructor
ProcessFactory::ProcessFactory() : processHandle(nullptr) {
}

Process ProcessFactory::create(const RM_PROCESS_INFO& info) const {
	processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.Process.dwProcessId);
	if (!processHandle) {
		// Handle error or return a default-constructed Process
		return {info, L"nul", L"0:0:0:0", 0, L"Unknown"};
	}

	std::wstring path = findPath();
	std::wstring date = findCreationDate(info.Process.ProcessStartTime);
	DWORD parentID = findParentId(info.Process.dwProcessId);
	std::wstring typeStr = TYPES.at(info.ApplicationType);
	CloseHandle(processHandle);
	return {info, path, date, parentID, typeStr};
}

std::wstring ProcessFactory::findPath() const {
	std::wstring path;
	if (processHandle) {
		std::vector<wchar_t> pathBuffer(MAX_PATH);
		DWORD length = MAX_PATH;
		if (QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &length)) {
			path = std::wstring(pathBuffer.data(), length);
		}
	}
	return path;
}

std::wstring ProcessFactory::findCreationDate(const FILETIME& ProcessStartTime) {
	SYSTEMTIME time;
	if (!FileTimeToSystemTime(&ProcessStartTime, &time)) {
		// Handle error if necessary
	}
	std::wstringstream os{};
	os << time.wHour + 2 << ":" << time.wMinute << ":" << time.wSecond << ":" << time.wMilliseconds;
	return os.str();
}

DWORD ProcessFactory::findParentId(DWORD pid) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(h, &pe)) {
		do {
			if (pe.th32ProcessID == pid) {
				CloseHandle(h);
				return pe.th32ParentProcessID;
			}
		} while (Process32Next(h, &pe));
	}
	CloseHandle(h);
	return 0;
	// TODO: maybe std::optional
}