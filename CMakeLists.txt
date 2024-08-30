cmake_minimum_required(VERSION 3.14)

# delete .out/CmakeFiles folder to make this work
option(PRODUCTION_BUILD "Make this a production build" OFF)

# project name
set(PROJECT_NAME "LockHunter")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED ON)


# Set the CMP0069 policy, because warning annoying
if(POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW)
endif()
if(POLICY CMP0111)
    cmake_policy(SET CMP0111 NEW)
endif()


# /Zi and /GL are incompatible, so here
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

if(MSVC)
    # Set MSVC runtime library
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Release>:Release>")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Show all warnings, but stupid ones
    add_compile_options(/W4 /EHsc /arch:AVX2)

    # Disable CRT secure warnings
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# Enable Hot Reload for MSVC compilers if supported, came with the default file
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project("${PROJECT_NAME}")

# .clang-tidy stuff
# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# add_definitions(-DSOME_DEFINITION)

# Add source files recursively from the src directory
file(GLOB_RECURSE MY_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/cpp-httplib")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/json")

# Include directories
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include/"
"${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/RestartManager" "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/SHA1")

# Add source to this project's executable
add_executable(${PROJECT_NAME} ${MY_SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE httplib ws2_32 nlohmann_json::nlohmann_json
"${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/RestartManager/rstrtmgr.lib")

if(PRODUCTION_BUILD)
    # setup the ASSETS_PATH macro to be in the root folder of your exe
    target_compile_definitions(${PROJECT_NAME} PUBLIC RESOURCES_PATH="./resources/") 
    # remove the option to debug asserts.
    target_compile_definitions(${PROJECT_NAME} PUBLIC PRODUCTION_BUILD=1) 
else()
    # This is useful to get an ASSETS_PATH in your IDE during development
    target_compile_definitions(${PROJECT_NAME} PUBLIC RESOURCES_PATH="${CMAKE_CURRENT_SOURCE_DIR}/resources/")
    target_compile_definitions(${PROJECT_NAME} PUBLIC PRODUCTION_BUILD=0) 
endif()