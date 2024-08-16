#pragma once
#ifndef _H_LOCKHUNTER
#define _H_LOCKHUNTER

#include <iostream>
#include <set>
#include <string>
#include <filesystem>
#include "ProcessHandler.h"
#include "FileLockDetector.h"
#include "VirusTotal.h"

enum LockHunterOption : int {
	INVALID,
	DELETE_FILE,
	UNLOCK_FILE,
	SHOW_PROCESSES_INFO,
	SCAN_PROCESSES_FOR_VIRUS,
	EXIT
};

class LockHunter final {
  public:
	// Constructors
	LockHunter(const std::wstring& filePath);
	LockHunterOption getChoice();
	void handleChoice(LockHunterOption choice);

  private:
	// Methods
	void unlockFile();

	// Fields
	std::set<Process> processes;
	std::wstring filePath;
	VirusTotal scanner;
};
#endif // ! _H_LOCKHUNTER
