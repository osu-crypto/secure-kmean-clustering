
project(ivory)

#############################################
#              Build ivory                  #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
add_library(ivory ${SRCS})
target_include_directories(ivory PUBLIC ${CMAKE_SOURCE_DIR}/ivory)



###########################################################################  
#                        Link external libraries                          #
#                        -----------------------                          #
#                                                                         #
#  Define the expected location for miracl and boost.                     #
#  Boost will be found using the findBoost  module in CMake               #
#  It should look in the location specified and then look elsewhere       # 
#                                                                         #
###########################################################################  


#                 Link libOTe               
###########################################################################

if(NOT IS_DIRECTORY ${libOTe_Dirs}) 
  message(FATAL_ERROR "Bad libOTe location. libOTe_Dirs=${libOTe_Dirs}" )
endif()


find_library(
	libOTe_LIB
	NAMES libOTe
	HINTS "${libOTe_Dirs}/lib/")
	

find_library(
	cryptoTools_LIB
	NAMES cryptoTools
	HINTS "${libOTe_Dirs}/lib/")

if(NOT EXISTS "${libOTe_LIB}")
  message(FATAL_ERROR "Failed to find libOTe at ${libOTe_LIB}" )
else()
  target_include_directories(ivory PUBLIC ${libOTe_Dirs}) 
  target_include_directories(ivory PUBLIC ${libOTe_Dirs}/cryptoTools) 
endif()



## Miracl
###########################################################################

set(Miracl_Dirs "${libOTe_Dirs}/cryptoTools/thirdparty/miracl/")

set(Miracl_Lib_Dirs "${Miracl_Dirs}/miracl/source/")
find_library(MIRACL_LIB NAMES miracl  HINTS "${Miracl_Lib_Dirs}")

# if we cant fint it, throw an error
if(NOT MIRACL_LIB)
    message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
endif()
message(STATUS "MIRACL_LIB:  ${MIRACL_LIB}")

#include_directories("${Miracl_Dirs}") 

target_include_directories(ivory PUBLIC "${Miracl_Dirs}") 
#target_link_libraries(ivory ${MIRACL_LIB})


## Boost
###########################################################################

set(BOOST_ROOT "${libOTe_Dirs}/cryptoTools/thirdparty/boost/")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     OFF)

find_package(Boost COMPONENTS system thread)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif() 

#include_directories(${Boost_INCLUDE_DIR}) 

target_include_directories(ivory PUBLIC ${Boost_INCLUDE_DIR}) 
#target_link_libraries(ivory ${Boost_LIBRARIES})

message(STATUS "Boost_LIBS ${Boost_LIBRARIES}" )


#                 Link NTL                  
###########################################################################
set(NTL_Lib_Dirs "${NTL_Dirs}/src/")
set(NTL_Include_Dirs "${NTL_Dirs}/include/")

# default location for NTL
set(NTL_LIB "${NTL_Lib_Dirs}libntl.a")


if(NOT EXISTS "${NTL_LIB}")
  # we failed to find it, try using find_library
  find_library(
    NTL_LIB 
    NAMES ntl  
    HINTS NTL_Lib_Dirs)
  
  # if we still cant fint it, throw an error
  if(NOT NTL_LIB)
    Message(${NTL_LIB})
    message(FATAL_ERROR "Failed to find NTL at ${NTL_Lib_Dirs} or at system locations." )
  endif()
else()
  target_include_directories(ivory PUBLIC ${NTL_Include_Dirs})
  #message(" ----  NTL -----  ${NTL_Include_Dirs}")
endif()







target_link_libraries(ivory ${libOTe_LIB}  ${cryptoTools_LIB} ${NTL_LIB}  ${Boost_LIBRARIES}  ${MIRACL_LIB})


