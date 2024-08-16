#pragma once

#include <windows.h>
#include <RestartManager.h>
#include <vector>
#include <set>
#include <string>
#include <stdexcept>
#include "ProcessHandler.h"

class FileLockDetector {
  public:
	FileLockDetector();
	~FileLockDetector() noexcept;

	void findProcessesLockingFile(const std::wstring& filePath, std::set<Process>& processInfoSet) const;

  private:
	DWORD session;
	WCHAR sessionKey[CCH_RM_SESSION_KEY + 1];
};