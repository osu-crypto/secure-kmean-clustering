cmake_minimum_required (VERSION 3.6)

project("ivory")


set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -O3 -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")



#############################################
#       Library/includes locations          #
#############################################

# default location for libOTe
set(libOTe_Dirs "${CMAKE_SOURCE_DIR}/../libOTe/")
#include_directories("${libOTe_Dirs}/libOTe/") 
#link_directories("${libOTe_Dirs}/lib/")

# default location for miracl
#set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/")
#include_directories("${Miracl_Dirs}") 
#link_directories("${Miracl_Dirs}/miracl/source/")

# default location for NTL
set(NTL_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/ntl/")
#include_directories("${NTL_Dirs}/include/")
#link_directories("${NTL_Dirs}/src/") 

# default location for Boost
#set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")


#############################################
#            Build cryptoTools              #
#############################################
#add_subdirectory(../libOTe)
#include_directories(cryptoTools)


#############################################
#               Build ivory                 #
#############################################

include_directories(${CMAKE_SOURCE_DIR})
add_subdirectory(ivory)


#############################################
#           Build ivory Tests              #
#############################################
add_subdirectory(ivoryTests)
include_directories(ivoryTests)


#############################################
#              Build Frontend               #
#############################################
#add_subdirectory(frontend)
file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
add_executable(frontend.exe  ${SRC_FRONTEND})
target_link_libraries(frontend.exe ivoryTests)
target_link_libraries(frontend.exe ivory)

