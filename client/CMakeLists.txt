cmake_minimum_required(VERSION 3.5)
project(client)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)
file(GLOB INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/*.h ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
aux_source_directory(. SRC_LISTS)
# add_library(${PROJECT_NAME} "${SRC_LISTS}")
# set_target_properties(${PROJECT_NAME} PROPERTIES INSTALL_NAME_DIR ${CMAKE_INSTALL_PREFIX}/lib VERSION 0.1.1 SOVERSION 0)

add_executable(${PROJECT_NAME} "${SRC_LISTS}")
target_link_libraries(${PROJECT_NAME} ssl crypto pthread)
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(FILES ${INCLUDES} DESTINATION include)
