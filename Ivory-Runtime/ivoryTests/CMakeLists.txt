
#project(ivoryTests)

 

#############################################
#               Build ivoryTests            #
#############################################

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/ivoryTests)


add_library(ivoryTests ${SRCS})

target_link_libraries(ivoryTests ivory)
