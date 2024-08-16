#ifndef PROCESSFACTORY_H
#define PROCESSFACTORY_H

#include "ProcessHandler.h"
#include <string>
#include <tlhelp32.h>
#include <map>

class ProcessFactory {
  public:
	// Default constructor
	ProcessFactory();
	~ProcessFactory() = default;

	// Create a Process instance
	Process create(const RM_PROCESS_INFO& info) const;

  private:
	// not mutating it, but am reassigning it
	mutable HANDLE processHandle;

	// Methods to find path and creation date
	std::wstring findPath() const;
	static std::wstring findCreationDate(const FILETIME& ProcessStartTime);

	static DWORD findParentId(DWORD pid);

	const std::map<RM_APP_TYPE, std::wstring> TYPES = {{RmUnknownApp, L"Unknown"},
													   {RmMainWindow, L"Main Window"},
													   {RmOtherWindow, L"Other Window"},
													   {RmService, L"Windows Service"},
													   {RmExplorer, L"Windows Explorer"},
													   {RmConsole, L"Console Application"},
													   {RmCritical, L"Critical System Process"}};
};

#endif // PROCESSFACTORY_H
