#project(frontend)


file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})


add_executable(frontend  ${SRCS})

target_link_libraries(frontend libOTe Tests cryptoTools ivoryTests ivory)