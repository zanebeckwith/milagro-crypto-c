# Example programs

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_BINARY_DIR}/include )

add_executable (amcl_build amcl_build.c)
target_link_libraries (amcl_build amcl_curve) 

add_executable (testecdh testecdh.c)
target_link_libraries (testecdh amcl_ecc) 
add_executable (testrsa testrsa.c)
target_link_libraries (testrsa amcl_rsa) 

if(BUILD_X509)
  add_executable (testx509 testx509.c)
  target_link_libraries (testx509 amcl_x509) 
endif(BUILD_X509)

if(BUILD_MPIN)
  add_executable (testmpin testmpin.c)
  target_link_libraries (testmpin amcl_mpin)
if(USE_DVS)
  add_executable (testdvs testdvs.c)
  target_link_libraries (testdvs amcl_mpin)
endif(USE_DVS) 
endif(BUILD_MPIN)

if(BUILD_WCC)
  add_executable (testwcc testwcc.c)
  add_executable (testwcc_tp testwcc_tp.c)
  add_executable (testwcc_dta testwcc_dta.c)
  target_link_libraries (testwcc amcl_wcc) 
  target_link_libraries (testwcc_tp amcl_wcc) 
  target_link_libraries (testwcc_dta amcl_wcc) 
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
