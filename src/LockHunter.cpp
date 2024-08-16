#include "LockHunter.h"
#include <filesystem>
#include <iostream>
#include <ios>
#include <limits>

// causes collision
#undef max
#undef min

LockHunter::LockHunter(const std::wstring& _filePath)
	: filePath(_filePath), scanner("aaaaf5fb0ecaff8bcf5ef7ae0de82736217b096e4f57040abeaa0fd65eabb11b") {
	if (!std::filesystem::exists(_filePath)) {
		throw std::runtime_error("File does not exist");
	}

	FileLockDetector detector;
	detector.findProcessesLockingFile(filePath, processes);
	if (processes.empty()) {
		throw std::runtime_error("File isn't even locked my good sire");
	}
}

LockHunterOption LockHunter::getChoice() {

	std::wcout << L"File \"" << filePath << L"\"\n" << processes.size() << L" Locking processes\n";

	for (const auto& process : processes)
		std::wcout << L" - " << process.getName() << L'\n';

	std::wcout << L"\nOPTIONS\n"
			   << L" [1] Delete file\n"
			   << L" [2] Unlock file\n"
			   << L" [3] Get more info about locking processes\n"
			   << L" [4] Scan locking processes for viruses (VirusTotal)\n"
			   << L" [5] Exit" << std::endl
			   << L"$ ";

	int choice = 0;
	std::wcin >> choice;

	// Check if the input failed (i.e., non-integer input)
	if (std::wcin.fail()) {
		std::wcin.clear();
		std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
		return LockHunterOption::INVALID;
	}
	// Validate the choice
	if (choice < LockHunterOption::DELETE_FILE || choice > LockHunterOption::EXIT) {
		return LockHunterOption::INVALID;
	}

	return static_cast<LockHunterOption>(choice);
}

void LockHunter::handleChoice(LockHunterOption choice) {
	switch (choice) {
	case LockHunterOption::DELETE_FILE:
		if (filePath.empty()) {
			std::cout << "File doesn't exist anymore\n";
			break;
		}
		unlockFile();
		if (!DeleteFileW(filePath.c_str())) {
			DWORD error = GetLastError();
			std::wcerr << L"Failed to delete the file. Error code: " << error << std::endl;
		}

		filePath = L"";
		std::cout << "File deleted.\n";
		break;

	case LockHunterOption::UNLOCK_FILE:
		if (processes.empty()) {
			std::cout << "No processes to terminate";
			break;
		}
		unlockFile();
		std::cout << "File unlocked.\n";
		break;

	case LockHunterOption::SHOW_PROCESSES_INFO:
		for (const auto& proc : processes) {
			std::wcout << proc << std::endl;
		}
		break;

	case LockHunterOption::SCAN_PROCESSES_FOR_VIRUS:
		std::cout << "SCANS RESULTS\n";
		for (const auto& proc : processes) {
			std::wcout << " * \"" << proc.getName() << "\" - ";
			std::cout << scanner.scan(proc.getPath()).message << "\n--------------------------------------\n";
		}
		break;

	case LockHunterOption::EXIT:
		std::cout << "Exiting.\n";
		break;

	case LockHunterOption::INVALID:
		std::cerr << "Invalid choice. Please try again.\n";
		break;
	}
}

void LockHunter::unlockFile() {
	std::vector<Process> processesToRemove;

	for (const auto& proc : processes) {
		if (proc.terminate()) {
			processesToRemove.push_back(proc);
		}
	}

	for (const auto& proc : processesToRemove) {
		processes.erase(proc);
	}
}
