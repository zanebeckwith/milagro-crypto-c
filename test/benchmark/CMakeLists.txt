# Benchmark

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_BINARY_DIR}/include )

add_executable (benchtest_ec benchtest_ec.c)
add_executable (benchtest_rsa benchtest_rsa.c)
# Link the executable to the libraries
target_link_libraries (benchtest_ec amcl) 
target_link_libraries (benchtest_rsa rsa)

if(AMCL_CHOICE MATCHES "BN" OR AMCL_CHOICE MATCHES "BLS")
  add_executable (benchtest_pair benchtest_pair.c)
  # Link the executable to the libraries
  target_link_libraries (benchtest_pair amcl) 
endif(AMCL_CHOICE MATCHES "BN" OR AMCL_CHOICE MATCHES "BLS")