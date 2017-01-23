# Benchmark

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_BINARY_DIR}/include )

#define macro to simplify adding tests
macro (do_test arg result)
  add_test (${arg} ${TARGET_SYSTEM_EMULATOR} ${arg}${CMAKE_EXECUTABLE_SUFFIX})
  set_tests_properties (${arg}
    PROPERTIES PASS_REGULAR_EXPRESSION ${result}
    )
endmacro ()

# smoke tests  
add_executable (benchtest_ec benchtest_ec.c)
add_executable (benchtest_rsa benchtest_rsa.c)
# Link the executable to the libraries
target_link_libraries (benchtest_ec amcl) 
target_link_libraries (benchtest_rsa rsa) 
# run tests
do_test (benchtest_ec "SUCCESS")
do_test (benchtest_rsa "SUCCESS")


# Arithmetics test fp2 for pairing-friendly curves
if((AMCL_CHOICE STREQUAL "BLS455") OR (AMCL_CHOICE STREQUAL "BLS383") OR (AMCL_CHOICE STREQUAL "BN254_CX") OR (AMCL_CHOICE STREQUAL "BN254") OR (AMCL_CHOICE STREQUAL "BN254_T2") OR (AMCL_CHOICE STREQUAL "BN254_T") OR (AMCL_CHOICE STREQUAL "BN454") OR (AMCL_CHOICE STREQUAL "BN646")) 
 
endif((AMCL_CHOICE STREQUAL "BLS455") OR (AMCL_CHOICE STREQUAL "BLS383") OR (AMCL_CHOICE STREQUAL "BN254_CX") OR (AMCL_CHOICE STREQUAL "BN254") OR (AMCL_CHOICE STREQUAL "BN254_T2") OR (AMCL_CHOICE STREQUAL "BN254_T") OR (AMCL_CHOICE STREQUAL "BN454") OR (AMCL_CHOICE STREQUAL "BN646")) 

