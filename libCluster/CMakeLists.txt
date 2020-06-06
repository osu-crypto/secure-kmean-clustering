
#project(libOTe_Tests)

file(GLOB_RECURSE SRCS *.cpp)
add_library(libCluster STATIC ${SRCS})

target_include_directories(libCluster PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(libCluster libOTe cryptoTools ivory)
