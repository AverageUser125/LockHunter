#include <windows.h>
#include <iostream>
#include <string>
#include <conio.h>

HANDLE openFile(const std::wstring& path);
HANDLE createFile(const std::wstring& path);

constexpr auto FILE_NAME = L"./test.txt";

int main()
{
	
	HANDLE file = openFile(FILE_NAME);
	
	if (file != INVALID_HANDLE_VALUE && LockFile(file, 0, 0, 1024, 0))
	{
		std::wcout << "File \"" << FILE_NAME << "\" is locked." << std::endl;

		auto a = getch();

		UnlockFile(file, 0, 0, 1024, 0);
		std::wcout << "File \"" << FILE_NAME << "\" unlocked." << std::endl;
	
	}
	else
	{
		std::wcout << "Cannot lock file \"" << FILE_NAME << "\": " << GetLastError() << std::endl;
	}

}

HANDLE openFile(const std::wstring& path)
{
	
	HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, 0, NULL, CREATE_NEW, 0, NULL);

	if (file == INVALID_HANDLE_VALUE)
		return createFile(path);

}

HANDLE createFile(const std::wstring& path) 
{
	return CreateFileW(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}
