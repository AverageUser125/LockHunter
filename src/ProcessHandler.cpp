#include "Process.h"
#include <cwctype>	// For wcscmp
#include <iostream> // For std::wostream
#include "ProcessHandler.h"

// Constructor
Process::Process(const RM_PROCESS_INFO& _info, std::wstring _path, std::wstring _date, const DWORD _parentID,
				 std::wstring _typeStr)
	: info(_info), path(std::move(_path)), creationDate(std::move(_date)), parentID(_parentID),
	  typeStr(std::move(_typeStr)) {
}

// Comparison operator
bool Process::operator<(const Process& other) const {
	if (info.Process.dwProcessId != other.info.Process.dwProcessId) {
		return info.Process.dwProcessId < other.info.Process.dwProcessId;
	}
	return wcscmp(info.strAppName, other.info.strAppName) < 0;
}

const std::wstring& Process::getPath() const {
	return path;
}

std::wostream& operator<<(std::wostream& os, const Process& proc) {
	auto [kernelSpaceTime, userSpaceTime] = proc.getTimeInLands();

	os << L"Process ID: " << proc.info.Process.dwProcessId << L"\n"
	   << L"Type: " << proc.typeStr << L"\n"
	   << L"Application Name: " << proc.info.strAppName << L"\n"
	   << L"Path: " << proc.path << L"\n"
	   << L"Creation Date: " << proc.creationDate << L"\n"
	   << L"Kernal Time: " << kernelSpaceTime << L"ns\n"
	   << L"User Time: " << userSpaceTime << L"ns\n"
	   << L"Parent PID: " << proc.parentID << L"\n";

	return os;
}

std::wstring Process::getName() const {
	return info.strAppName;
}

// returns success or not
bool Process::terminate() const {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, info.Process.dwProcessId);
	if (!hProcess)
		return false;
	const bool success = TerminateProcess(hProcess, 1);
	CloseHandle(hProcess);
	return success;
}

// Static function definition
uint64_t Process::lpfiletimeToUll(const FILETIME& pTime) {
	return static_cast<uint64_t>(pTime.dwHighDateTime) << (sizeof(uint64_t) / 2) | pTime.dwLowDateTime;
}

// Method definition
Process::ProcessLifeTime Process::getTimeInLands() const {
	FILETIME exitTime;
	FILETIME creationTime;
	FILETIME kernelTime;
	FILETIME userTime;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.Process.dwProcessId);
	if (!hProcess) {
		return {0, 0};
		// TODO:
	}
	// note - creationTime & exitTime are unused
	if (!GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
		// TODO:
	}

	return {lpfiletimeToUll(kernelTime), lpfiletimeToUll(userTime)};
}