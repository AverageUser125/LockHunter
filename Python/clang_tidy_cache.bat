@echo off
rem clang-tidy cache wrapper script

rem Set the script directory (same directory as the script)
set script_dir=%~dp0

rem Set the cache directory (relative to script location)
set CTCACHE_DIR=%script_dir%\..\cache\clangTidyCache

rem Path to the Python virtual environment's Python interpreter
set venv_python=%script_dir%\venv\Scripts\python.exe

rem Check if CTCACHE_SKIP is set and not equal to 0
if not "%CTCACHE_SKIP%" == "" if not "%CTCACHE_SKIP%" == "0" exit /b 0

rem Source the configuration file if it exists
if exist "%config_file%" (
    call :sourceConfig "%config_file%"
)

rem Set default for CTCACHE_CLANG_TIDY if not set
set CTCACHE_CLANG_TIDY=D:\\apps\\VisualStudio\\app\\VC\\Tools\\Llvm\\x64\\bin\\clang-tidy.exe

"%venv_python%" "%script_dir%\clang_tidy_cache.py" "%CTCACHE_CLANG_TIDY%" --fix --config-file="%script_dir%/../.clang-tidy" %*
rem clang-format -i -style=file:%script_dir%/../.clang-format %script_dir%/../src/*.cpp %script_dir%/../include/*.h

exit /b 0

:sourceConfig
rem Source the configuration file
for /f "usebackq tokens=*" %%i in (%1) do set "%%i"
exit /b 0
