cmake_minimum_required (VERSION 2.8)

project(main)

if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

	############################################
	#           Flag and #defines              #
	############################################
	add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
	set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -Wno-strict-overflow  -fPIC -Wno-ignored-attributes")
	set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")
	
	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb -rdynamic")
	
	############################################
	#           Build mode checks              #
	############################################
	
	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
	  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with -DCMAKE_BUILD_TYPE=Release  instead of ${CMAKE_BUILD_TYPE}")

		if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
		  #message(WARNING "Debug build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release") 
		  #message(WARNING "Release build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL  "RELWITHDEBINFO")
		  #message(WARNING "RELWITHDEBINFO=Release with debug info build.")
		else()
		  message(ERROR ": Unknown build type - ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO\n\n" )
		endif()
	endif()


endif()
 
############################################
#       Library/includes locations          #
#############################################

# default location for libOTe
set(libOTe_Dirs "${CMAKE_SOURCE_DIR}/libOTe/")

# default location for NTL
set(NTL_Dirs "${CMAKE_SOURCE_DIR}/Ivory-Runtime/thirdparty/linux/ntl/")


#############################################
#    Build cryptoTools (common utilities)   #
#############################################
#include_directories(cryptoTools)
add_subdirectory(libOTe/cryptoTools)


#############################################
#               Build libOTe                #
#############################################
include_directories(libOTe)
add_subdirectory(libOTe/libOTe)

#############################################
#               Build ivory                #
#############################################
include_directories(Ivory-Runtime)
add_subdirectory(Ivory-Runtime/ivory)

#############################################
#               Build Tests                #
#############################################
include_directories(Tests)
add_subdirectory(Tests)

#############################################
#               Build ivoryTests                #
#############################################
#include_directories(Ivory-Runtime/ivoryTests)
#add_subdirectory(Ivory-Runtime/ivoryTests)



#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)