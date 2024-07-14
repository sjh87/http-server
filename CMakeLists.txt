cmake_minimum_required(VERSION 3.13)

project(http-server-starter-cpp)

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

set(CMAKE_CXX_STANDARD 23) # Okay, CC. If you say so.
set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(server ${SOURCE_FILES})

target_link_libraries(server PRIVATE 
    Threads::Threads
    ZLIB::ZLIB
)

target_include_directories(server PRIVATE ${ZLIB_INCLUDE_DIRS})
