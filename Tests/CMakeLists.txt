
#project(libOTe_Tests)

file(GLOB_RECURSE SRCS *.cpp)
add_library(Tests STATIC ${SRCS})

target_include_directories(Tests PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(Tests libOTe cryptoTools ivory)
