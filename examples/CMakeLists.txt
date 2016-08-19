# Example programs

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include )

add_executable (amcl_build amcl_build.c)
target_link_libraries (amcl_build amcl) 

add_executable (testecdh testecdh.c)
target_link_libraries (testecdh ecdh) 
add_executable (testrsa testrsa.c)
target_link_libraries (testrsa rsa) 

if(BUILD_MPIN)
  add_executable (testmpin testmpin.c)
  target_link_libraries (testmpin mpin) 
endif(BUILD_MPIN)

if(BUILD_WCC)
  add_executable (testwcc testwcc.c)
  add_executable (testwcc_tp testwcc_tp.c)
  add_executable (testwcc_dta testwcc_dta.c)
  target_link_libraries (testwcc wcc) 
  target_link_libraries (testwcc_tp wcc) 
  target_link_libraries (testwcc_dta wcc) 
endif(BUILD_WCC)

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_PREFIX} DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

install(DIRECTORY DESTINATION bin DIRECTORY_PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)

install(TARGETS amcl_build DESTINATION bin PERMISSIONS
        OWNER_WRITE OWNER_READ OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE)
