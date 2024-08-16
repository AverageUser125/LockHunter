#include "FileLockDetector.h"
#include "ProcessFactory.h"

FileLockDetector::FileLockDetector() : session(0), sessionKey() {
	if (RmStartSession(&session, 0, sessionKey) != ERROR_SUCCESS) {
		throw std::runtime_error("Failed to start Restart Manager session");
	}
}

FileLockDetector::~FileLockDetector() noexcept {
	RmEndSession(session);
}

void FileLockDetector::findProcessesLockingFile(const std::wstring& filePath, std::set<Process>& processInfoSet) const {
	LPCWSTR path = filePath.c_str();
	if (RmRegisterResources(session, 1, &path, 0, nullptr, 0, nullptr) != ERROR_SUCCESS) {
		throw std::runtime_error("Failed to register resources with Restart Manager");
	}

	DWORD dwReason{};
	UINT nProcInfoNeeded{};
	UINT processesCount = 1; // Initial buffer size
	std::vector<RM_PROCESS_INFO> lockingProcesses(processesCount);

	ProcessFactory factory;

	while (true) {
		DWORD result = RmGetList(session, &nProcInfoNeeded, &processesCount, lockingProcesses.data(), &dwReason);
		if (result == ERROR_SUCCESS) {
			for (UINT i = 0; i < processesCount; ++i) {
				Process newProc = factory.create(lockingProcesses[i]);
				processInfoSet.insert(newProc);
			}
			break; // Exit loop after successful retrieval
		}
		if (result == ERROR_MORE_DATA) {
			// Increase buffer size and retry
			processesCount *= 2; // Double the buffer size
			lockingProcesses.resize(processesCount);
		} else {
			throw std::runtime_error("Failed to get process list from Restart Manager with error code: " +
									 std::to_string(result));
		}
	}
}