#include <iostream>
#include "LockHunter.h"
#include <codecvt>

void clearConsole() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE)
		return;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	COORD topLeft = {0, 0};
	DWORD written{};
	DWORD size = csbi.dwSize.X * csbi.dwSize.Y;
	FillConsoleOutputCharacter(hConsole, ' ', size, topLeft, &written);
	SetConsoleCursorPosition(hConsole, topLeft);
}

std::wstring utf8ToWstring(const std::string& str) {
	if (str.empty())
		return std::wstring();

	int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
	std::wstring wstr(sizeNeeded, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], sizeNeeded);

	return wstr;
}

int main(int argc, char* argv[]) {
	clearConsole();

	try {
		std::wstring filePath;

		if (argc > 1) {
			// Use the dropped file path
			filePath = utf8ToWstring(argv[1]);
		} else {

            #if !defined(NDEBUG) || defined(_DEBUG)
			filePath = L"" RESOURCES_PATH "test.txt";
			#else
			std::cerr << "Error please input some file\n";
			return EXIT_FAILURE;
			#endif
		}

		// Create an instance of LockHunter
		LockHunter lockHunter(filePath);

		LockHunterOption choice = LockHunterOption::INVALID;

		do {
			// Get user choice
			choice = lockHunter.getChoice();

			// Handle the choice
			clearConsole();

			lockHunter.handleChoice(choice);

		} while (choice != LockHunterOption::EXIT);

	} catch (const std::exception& ex) {
		std::cerr << "Exception: " << ex.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}