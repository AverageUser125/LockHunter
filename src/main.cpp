#include <iostream>
#include "LockHunter.h"

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

int main() {
	clearConsole();

	try {
		// Initialize the file path
		const std::wstring filePath = L"" RESOURCES_PATH "test.txt";

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