#ifndef PROCESS_H
#define PROCESS_H

#include <windows.h>
#include <RestartManager.h>
#include <string>
#include <psapi.h>
#include <vector>
#include <tchar.h>
#include <sstream>

class Process {
  public:
	struct ProcessLifeTime {
		uint64_t kernelTime, userTime;
	};

	// Constructor that takes RM_PROCESS_INFO and additional information
	Process::Process(const RM_PROCESS_INFO& _info, std::wstring _path, std::wstring _date, const DWORD _parentID,
					 std::wstring _typeStr);


	std::wstring getName() const;
	bool terminate() const;

	static uint64_t lpfiletimeToUll(const FILETIME& pTime);
	Process::ProcessLifeTime getTimeInLands() const;

	// Comparison operator for use in std::set
	bool operator<(const Process& other) const;
	friend std::wostream& operator<<(std::wostream& os, const Process& proc);

	const std::wstring& getPath() const;

  private:
	RM_PROCESS_INFO info;
	std::wstring path;
	std::wstring creationDate;
	DWORD parentID;
	std::wstring typeStr;
};


#endif // PROCESS_H
