# Tests

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

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

# create a smoke test
function(SMOKE_TEST test_name test_file dependencies expected_response)
  add_executable (${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
  # Link the executable to the libraries
  target_link_libraries (${test_name} ${dependencies})
  # run test
  do_test (${test_name} ${expected_response})
endfunction(SMOKE_TEST)

# create a test with testVectors
function(TV_TEST test_name test_file dependencies expected_response test_vector parameter)
  # set test
  add_executable (${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
  # Link the executable to the libraries
  target_link_libraries (${test_name} ${dependencies})
  # test
  add_test(NAME ${test_name} COMMAND ${TARGET_SYSTEM_EMULATOR} ${test_name} ${test_vector} ${parameter})
  set_tests_properties (${test_name} PROPERTIES PASS_REGULAR_EXPRESSION ${expected_response})
endfunction(TV_TEST)

# Test octet consistency
file (COPY test_octet_consistency.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
SMOKE_TEST ( test_octet_consistency test_octet_consistency.c amcl_core "SUCCESS")

# Test Version
file (COPY test_version.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
# SMOKE_TEST ( test_version test_version.c amcl_core "Version: ${AMCL_VERSION_MAJOR}.${AMCL_VERSION_MINOR}.${AMCL_VERSION_PATCH}")

# Test hash functions
file (COPY test_hash.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
TV_TEST (test_hash_256 test_hash.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/sha/256/SHA256ShortMsg.rsp" "sha256")
TV_TEST (test_hash_384 test_hash.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/sha/384/SHA384ShortMsg.rsp" "sha384")
TV_TEST (test_hash_512 test_hash.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/sha/512/SHA512ShortMsg.rsp" "sha512")

# Test AES-GCM
file (COPY test_aes_encrypt.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file (COPY test_aes_decrypt.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file (COPY test_gcm_encrypt.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file (COPY test_gcm_decrypt.c DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
TV_TEST (test_gcm_encrypt_128 test_gcm_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmEncryptExtIV128.rsp" "")
TV_TEST (test_gcm_encrypt_256 test_gcm_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmEncryptExtIV256.rsp" "")
TV_TEST (test_gcm_decrypt_128 test_gcm_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmDecrypt128.rsp" "")
TV_TEST (test_gcm_decrypt_256 test_gcm_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmDecrypt256.rsp" "")
TV_TEST (test_aes_encrypt_ECB_128 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT128.rsp" "ECB")
TV_TEST (test_aes_encrypt_ECB_256 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT256.rsp" "ECB")
TV_TEST (test_aes_encrypt_CBC_128 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT128.rsp" "CBC")
TV_TEST (test_aes_encrypt_CFB1_128 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CFB8MMT128.rsp" "CFB1")
TV_TEST (test_aes_encrypt_CBC_256 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT256.rsp" "CBC")
TV_TEST (test_aes_encrypt_CTR_128 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL128.rsp" "CTR")
TV_TEST (test_aes_encrypt_CTR_256 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL256.rsp" "CTR")
TV_TEST (test_aes_encrypt_CFB1_256 test_aes_encrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CFB8MMT256.rsp" "CFB1")
TV_TEST (test_aes_decrypt_ECB_128 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT128.rsp" "ECB")
TV_TEST (test_aes_decrypt_ECB_256 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT256.rsp" "ECB")
TV_TEST (test_aes_decrypt_CBC_128 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT128.rsp" "CBC")
TV_TEST (test_aes_decrypt_CFB1_128 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CFB8MMT128.rsp" "CFB1")
TV_TEST (test_aes_decrypt_CBC_256 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT256.rsp" "CBC")
TV_TEST (test_aes_decrypt_CTR_128 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL128.rsp" "CTR")
TV_TEST (test_aes_decrypt_CTR_256 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL256.rsp" "CTR")
TV_TEST (test_aes_decrypt_CFB1_256 test_aes_decrypt.c amcl_core "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/aes/CFB8MMT256.rsp" "CFB1")

# create new file replacing curve dependant parameters
function(CURVE_TESTS_SET tb tf tc nb base nbt m8 mt ct pf)
  set(bd "${tb}_${base}")

  if(NOT(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/test_big_arithmetics_${bd}.c"))
    # test BIG arithmetics
    file(READ "test_big_arithmetics_XXX.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_big_arithmetics_${bd}.c" "${tempc}")
    TV_TEST ("test_big_arithmetics_${bd}" "test_big_arithmetics_${bd}.c" "amcl_curve_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/big/test_vector_big.txt" "")

    # test BIG consistency
    file(READ "test_big_consistency_XXX.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_big_consistency_${bd}.c" "${tempc}")
    SMOKE_TEST ("test_big_consistency_${bd}" "test_big_consistency_${bd}.c" "amcl_curve_${tc}" "SUCCESS")
  endif()

  # Arithmetics test fp
  file(READ "test_fp_arithmetics_YYY.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_fp_arithmetics_${tf}.c" "${tempc}")
  TV_TEST ("test_fp_arithmetics_${tf}" "test_fp_arithmetics_${tf}.c" "amcl_curve_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/fp/test_vector_${tc}.txt" "")

  # Arithmetics test ecp
  file(READ "test_ecp_arithmetics_ZZZ.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
  string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_ecp_arithmetics_${tc}.c" "${tempc}")
  TV_TEST ("test_ecp_arithmetics_${tc}" "test_ecp_arithmetics_${tc}.c" "amcl_curve_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/ecp/test_vector_${tc}.txt" "")

  if(NOT(${pf} STREQUAL "NOT"))
  
    # Arithmetics test fp2 for pairing-friendly curves
    file(READ "test_fp2_arithmetics_YYY.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_fp2_arithmetics_${tf}.c" "${tempc}")
    TV_TEST ("test_fp2_arithmetics_${tf}" "test_fp2_arithmetics_${tf}.c" "amcl_pairing_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/fp2/test_vector_${tc}.txt" "")

    # Arithmetics test fp4 for pairing-friendly curves
    file(READ "test_fp4_arithmetics_YYY.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_fp4_arithmetics_${tf}.c" "${tempc}")
    TV_TEST ("test_fp4_arithmetics_${tf}" "test_fp4_arithmetics_${tf}.c" "amcl_pairing_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/fp4/test_vector_${tc}.txt" "")

    # Aritmetics test for ecp2 for pairing-friendly curves
    file(READ "test_ecp2_arithmetics_ZZZ.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_ecp2_arithmetics_${tf}.c" "${tempc}")
    TV_TEST ("test_ecp2_arithmetics_${tf}" "test_ecp2_arithmetics_${tf}.c" "amcl_pairing_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/ecp2/test_vector_${tc}.txt" "")

    if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
      # Aritmetics test output functions (used only for debug) - Linux specific code
      file(READ "test_output_functions_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_output_functions_${tf}.c" "${tempc}")
      TV_TEST ("test_output_functions_${tf}" "test_output_functions_${tf}.c" "amcl_pairing_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/output/test_vector_${tc}_${AMCL_CHUNK}.txt" "${PROJECT_BINARY_DIR}/Testing/Temporary/stdout.out")
    endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

    # if(${tf} STREQUAL "NIST256")
    #   add_executable (test_ecdh test_ecdh.c)
    #   add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
    #   add_executable (test_ecdsa_sign test_ecdsa_sign.c)
    #   add_executable (test_ecdsa_verify test_ecdsa_verify.c)
    #   # Link the executable to the libraries
    #   target_link_libraries (test_ecdh amcl_ecc) 
    #   target_link_libraries (test_ecdsa_keypair amcl_ecc) 
    #   target_link_libraries (test_ecdsa_sign amcl_ecc) 
    #   target_link_libraries (test_ecdsa_verify amcl_ecc) 
    #   # test
    #   add_test(NAME test_ecdh_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-256/KAS_ECC_CDH_PrimitiveTest.txt)
    #   set_tests_properties (test_ecdh_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    #   add_test(NAME test_ecdsa_keypair_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/KeyPair.rsp)
    #   set_tests_properties (test_ecdsa_keypair_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    #   add_test(NAME test_ecdsa_sign_NIST256_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha256Sign.rsp sha256)
    #   set_tests_properties (test_ecdsa_sign_NIST256_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    #   add_test(NAME test_ecdsa_sign_NIST256_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha512Sign.rsp sha512)
    #   set_tests_properties (test_ecdsa_sign_NIST256_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    #   add_test(NAME test_ecdsa_verify_NIST256_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha256Verify.rsp sha256)
    #   set_tests_properties (test_ecdsa_verify_NIST256_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    #   add_test(NAME test_ecdsa_verify_NIST256_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha512Verify.rsp sha512)
    #   set_tests_properties (test_ecdsa_verify_NIST256_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
    # endif(${tf} STREQUAL "NIST256")

    if(BUILD_MPIN)
      # test mpin
      file(READ "test_mpin_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_${tc}" "test_mpin_${tc}.c" "amcl_mpin_${tc}" "SUCCESS Error Code 0")

       # test mpin signature
      file(READ "test_mpin_sign_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_sign_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_sign_${tc}" "test_mpin_sign_${tc}.c" "amcl_mpin_${tc}" "TEST PASSED")

       # test mpin with good pin
      file(READ "test_mpin_good_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_good_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_good_${tc}" "test_mpin_good_${tc}.c" "amcl_mpin_${tc}" "SUCCESS Error Code 0")

       # test mpin with bad pin
      file(READ "test_mpin_bad_pin_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_bad_pin_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_bad_pin_${tc}" "test_mpin_bad_pin_${tc}.c" "amcl_mpin_${tc}" "FAILURE")

       # test mpin with bad token
      file(READ "test_mpin_bad_token_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_bad_token_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_bad_token_${tc}" "test_mpin_bad_token_${tc}.c" "amcl_mpin_${tc}" "FAILURE Invalid Token Error Code -19")

       # test mpin with expired time permit
      file(READ "test_mpin_expired_tp_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_expired_tp_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_expired_tp_${tf}" "test_mpin_expired_tp_${tc}.c" "amcl_mpin_${tc}" "FAILURE Invalid Token Error Code -19")

       # test mpin with time permit
      file(READ "test_mpin_tp_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_tp_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_tp_${tc}" "test_mpin_tp_${tc}.c" "amcl_mpin_${tc}" "SUCCESS Error Code 0")

      # if(USE_DVS)
      #   add_executable (test_mpin_dvs test_mpin_dvs.c)
      #   add_executable (test_mpin_dvs_wrong_pk test_mpin_dvs_wrong_pk.c)
      #   target_link_libraries (test_mpin_dvs amcl_mpin)
      #   target_link_libraries (test_mpin_dvs_wrong_pk amcl_mpin) 
      #   do_test (test_mpin_dvs "SUCCESS Error Code 0")
      #   do_test (test_mpin_dvs_wrong_pk "FAILURE Signature Verification Error Code -19")
      # endif(USE_DVS)

       # test mpin random
      file(READ "test_mpin_random_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_random_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpin_random_${tc}" "test_mpin_random_${tc}.c" "amcl_mpin_${tc}" "SUCCESS Error Code 0")

       # test mpin full with sha256
      file(READ "test_mpinfull_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_${tc}.c" "${tempc}")
      TV_TEST ("test_mpinfull_sha256_${tc}" "test_mpinfull_${tc}.c" "amcl_mpin_${tc}" "SUCCESS" "sha256" "")

      # test mpin full with sha384
      file(READ "test_mpinfull_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_${tc}.c" "${tempc}")
      TV_TEST ("test_mpinfull_sha384_${tc}" "test_mpinfull_${tc}.c" "amcl_mpin_${tc}" "SUCCESS" "sha384" "")

      # test mpin full with sha512
      file(READ "test_mpinfull_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_${tc}.c" "${tempc}")
      TV_TEST ("test_mpinfull_sha512_${tc}" "test_mpinfull_${tc}.c" "amcl_mpin_${tc}" "SUCCESS" "sha512" "")

      # test mpin full with time permit
      file(READ "test_mpinfull_tp_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_tp_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpinfull_tp_${tc}" "test_mpinfull_tp_${tc}.c" "amcl_mpin_${tc}" "SUCCESS")

      # test mpin full one pass
      file(READ "test_mpinfull_onepass_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_onepass_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpinfull_onepass_${tc}" "test_mpinfull_onepass_${tc}.c" "amcl_mpin_${tc}" "SUCCESS")

      # test mpin full one pass
      file(READ "test_mpinfull_random_ZZZ.c" tempc)
      string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
      string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
      string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
      file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpinfull_random_${tc}.c" "${tempc}")
      SMOKE_TEST ("test_mpinfull_random_${tc}" "test_mpinfull_random_${tc}.c" "amcl_mpin_${tc}" "SUCCESS")

      if(${tf} STREQUAL "BN254CX")
        # test mpin full one pass
        file(READ "test_mpin_vectors_ZZZ.c" tempc)
        string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
        string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
        string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
        file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_mpin_vectors_${tc}.c" "${tempc}")
        TV_TEST ("test_mpin_vectors_${tf}" "test_mpin_vectors_${tf}.c" "amcl_mpin_${tc}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/mpin/BN254_CX.txt" "")
      endif(${tf} STREQUAL "BN254CX")
    endif(BUILD_MPIN)

# if(BUILD_WCC)
#   add_executable (test_wcc_gcm test_wcc_gcm.c)
#   add_executable (test_wcc_sha256 test_wcc.c)
#   add_executable (test_wcc_sha384 test_wcc.c)
#   add_executable (test_wcc_sha512 test_wcc.c)
#   add_executable (test_wcc_random test_wcc_random.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_wcc_gcm amcl_wcc) 
#   target_link_libraries (test_wcc_sha256 amcl_wcc)
#   target_link_libraries (test_wcc_sha384 amcl_wcc) 
#   target_link_libraries (test_wcc_sha512 amcl_wcc) 
#   target_link_libraries (test_wcc_random amcl_wcc) 
#   # tests  
#   add_test(NAME test_wcc_sha256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_wcc_sha256 sha256)
#   set_tests_properties (test_wcc_sha256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_wcc_sha384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_wcc_sha384 sha384)
#   set_tests_properties (test_wcc_sha384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_wcc_sha512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_wcc_sha512 sha512)
#   set_tests_properties (test_wcc_sha512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   do_test (test_wcc_gcm "SUCCESS")
#   do_test (test_wcc_random "SUCCESS")
# endif(BUILD_WCC)  

  endif(NOT(${pf} STREQUAL "NOT"))

endfunction(CURVE_TESTS_SET tb tf tc nb base nbt m8 mt ct pf)

function(RSA_TESTS_SET tb tff nb base ml)
  set(bd "${tb}_${base}")

  if(NOT(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/test_big_arithmetics_${bd}.c"))
    # test BIG arithmetics
    file(READ "test_big_arithmetics_XXX.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_big_arithmetics_${bd}.c" "${tempc}")
    TV_TEST ("test_big_arithmetics_${bd}" "test_big_arithmetics_${bd}.c" "amcl_rsa_${tff}" "SUCCESS" "${PROJECT_SOURCE_DIR}/testVectors/big/test_vector_big.txt" "")

    # test BIG consistency
    file(READ "test_big_consistency_XXX.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test_big_consistency_${bd}.c" "${tempc}")
    SMOKE_TEST ("test_big_consistency_${bd}" "test_big_consistency_${bd}.c" "amcl_rsa_${tff}" "SUCCESS")
  endif()

endfunction(RSA_TESTS_SET tb tff nb base ml)

string(REGEX REPLACE "," ";" AMCL_CURVE ${AMCL_CURVE})
string(REGEX REPLACE "," ";" AMCL_RSA ${AMCL_RSA})

foreach(CURVE ${AMCL_CURVE})
  if(AMCL_CHUNK STREQUAL "64")
    if(CURVE STREQUAL "ED25519")
        CURVE_TESTS_SET("256" "25519" "ED25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "C25519")
        CURVE_TESTS_SET("256" "25519" "C25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "MONTGOMERY" "NOT")
    elseif(CURVE STREQUAL "NIST256")
        CURVE_TESTS_SET("256" "NIST256" "NIST256" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "BRAINPOOL")
        CURVE_TESTS_SET("256" "BRAINPOOL" "BRAINPOOL" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "ANSSI")
        CURVE_TESTS_SET("256" "ANSSI" "ANSSI" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "HIFIVE")
        CURVE_TESTS_SET("336" "HIFIVE" "HIFIVE" "42" "60" "336" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "GOLDILOCKS")
        CURVE_TESTS_SET("448" "GOLDILOCKS" "GOLDILOCKS" "56" "58" "448" "7" "GENERALISED_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST384")
        CURVE_TESTS_SET("384" "NIST384" "NIST384" "48" "56" "384" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "C41417")
        CURVE_TESTS_SET("416" "C41417" "C41417" "52" "60" "414" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_TESTS_SET("528" "NIST521" "NIST521" "66" "60" "521" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_TESTS_SET("256" "NIST521" "NUMS256W" "32" "56" "256" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS256E")
        CURVE_TESTS_SET("256" "256PME" "NUMS256E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS384W")
        CURVE_TESTS_SET("384" "384PM" "NUMS384W" "32" "56" "254" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS384E")
        CURVE_TESTS_SET("384" "384PM" "NUMS384E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS512W")
        CURVE_TESTS_SET("512" "512PM" "NUMS512W" "32" "56" "256" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS512E")
        CURVE_TESTS_SET("512" "512PM" "NUMS512E" "32" "56" "256" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "BN254")
        CURVE_TESTS_SET("256" "BN254" "BN254" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BN254CX")
        CURVE_TESTS_SET("256" "BN254CX" "BN254CX" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BLS383")
        CURVE_TESTS_SET("384" "BLS383" "BLS383" "48" "56" "383" "3" "NOT_SPECIAL" "WEIERSTRASS" "BLS")
    endif(CURVE STREQUAL "ED25519")
  elseif(AMCL_CHUNK STREQUAL "32")
    if(CURVE STREQUAL "ED25519")
        CURVE_TESTS_SET("256" "25519" "ED25519" "32" "29" "255" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "C25519")
        CURVE_TESTS_SET("256" "25519" "C25519" "32" "29" "255" "5" "PSEUDO_MERSENNE" "MONTGOMERY" "NOT")
    elseif(CURVE STREQUAL "NIST256")
        CURVE_TESTS_SET("256" "NIST256" "NIST256" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "BRAINPOOL")
        CURVE_TESTS_SET("256" "BRAINPOOL" "BRAINPOOL" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "ANSSI")
        CURVE_TESTS_SET("256" "ANSSI" "ANSSI" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "HIFIVE")
        CURVE_TESTS_SET("336" "HIFIVE" "HIFIVE" "42" "29" "336" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "GOLDILOCKS")
        CURVE_TESTS_SET("448" "GOLDILOCKS" "GOLDILOCKS" "56" "29" "448" "7" "GENERALISED_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST384")
        CURVE_TESTS_SET("384" "NIST384" "NIST384" "48" "29" "384" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "C41417")
        CURVE_TESTS_SET("416" "C41417" "C41417" "52" "29" "414" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_TESTS_SET("528" "NIST521" "NIST521" "66" "28" "521" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_TESTS_SET("256" "256PMW" "NUMS256W" "32" "28" "256" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS256E")
        CURVE_TESTS_SET("256" "256PME" "NUMS256E" "32" "29" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS384W")
        CURVE_TESTS_SET("384" "384PM" "NUMS384W" "32" "29" "254" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS384E")
        CURVE_TESTS_SET("384" "384PM" "NUMS384E" "32" "29" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS512W")
        CURVE_TESTS_SET("512" "512PM" "NUMS512W" "32" "29" "256" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS512E")
        CURVE_TESTS_SET("512" "512PM" "NUMS512E" "32" "29" "256" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "BN254")
        CURVE_TESTS_SET("256" "BN254" "BN254" "32" "28" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BN254CX")
        CURVE_TESTS_SET("256" "BN254CX" "BN254CX" "32" "28" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BLS383")
        CURVE_TESTS_SET("384" "BLS383" "BLS383" "48" "29" "383" "3" "NOT_SPECIAL" "WEIERSTRASS" "BLS")
    endif(CURVE STREQUAL "ED25519")
  endif(AMCL_CHUNK STREQUAL "64")
endforeach(CURVE)

foreach(RSA ${AMCL_RSA})
  if(RSA STREQUAL "2048")
    RSA_TESTS_SET("1024" "2048" "128" "58" "2")
  elseif(RSA STREQUAL "3072")
    RSA_TESTS_SET("384" "3072" "48" "56" "8")
  elseif(RSA STREQUAL "4096")
    RSA_TESTS_SET("512" "4096" "64" "60" "8")
  endif(RSA STREQUAL "2048")
endforeach(RSA)

# if(AMCL_CHOICE STREQUAL "NIST521")
#   message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
#   add_executable (test_ecdh test_ecdh.c)
#   add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
#   add_executable (test_ecdsa_sign test_ecdsa_sign.c)
#   add_executable (test_ecdsa_verify test_ecdsa_verify.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_ecdh amcl_ecc) 
#   target_link_libraries (test_ecdsa_keypair amcl_ecc) 
#   target_link_libraries (test_ecdsa_sign amcl_ecc) 
#   target_link_libraries (test_ecdsa_verify amcl_ecc)
#   # test
#   add_test(NAME test_ecdh_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-521/KAS_ECC_CDH_PrimitiveTest.txt)
#   set_tests_properties (test_ecdh_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_keypair_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/KeyPair.rsp)
#   set_tests_properties (test_ecdsa_keypair_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_sign_NIST521_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha256Sign.rsp sha256)
#   set_tests_properties (test_ecdsa_sign_NIST521_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_sign_NIST521_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha512Sign.rsp sha512)
#   set_tests_properties (test_ecdsa_sign_NIST521_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_verify_NIST521_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha256Verify.rsp sha256)
#   set_tests_properties (test_ecdsa_verify_NIST521_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_verify_NIST521_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha512Verify.rsp sha512)
#   set_tests_properties (test_ecdsa_verify_NIST521_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif(AMCL_CHOICE STREQUAL "NIST521")

# if((AMCL_CHOICE STREQUAL "NIST521")  AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
#   message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
#   add_executable (test_x509 test_x509.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_x509 x509)
#   # test
#   add_test(NAME test_x509_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/P521/x509-vect.txt)
#   set_tests_properties (test_x509_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST521")  AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

# if(AMCL_CHOICE STREQUAL "NIST384")
#   message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
#   add_executable (test_ecdh test_ecdh.c)
#   add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
#   add_executable (test_ecdsa_sign test_ecdsa_sign.c)
#   add_executable (test_ecdsa_verify test_ecdsa_verify.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_ecdh amcl_ecc) 
#   target_link_libraries (test_ecdsa_keypair amcl_ecc) 
#   target_link_libraries (test_ecdsa_sign amcl_ecc) 
#   target_link_libraries (test_ecdsa_verify amcl_ecc)
#   # test
#   add_test(NAME test_ecdh_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-384/KAS_ECC_CDH_PrimitiveTest.txt)
#   set_tests_properties (test_ecdh_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_keypair_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/KeyPair.rsp)
#   set_tests_properties (test_ecdsa_keypair_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_sign_NIST384_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha256Sign.rsp sha256)
#   set_tests_properties (test_ecdsa_sign_NIST384_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_sign_NIST384_SHA384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha384Sign.rsp sha384)
#   set_tests_properties (test_ecdsa_sign_NIST384_SHA384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_sign_NIST384_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha512Sign.rsp sha512)
#   set_tests_properties (test_ecdsa_sign_NIST384_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_verify_NIST384_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha256Verify.rsp sha256)
#   set_tests_properties (test_ecdsa_verify_NIST384_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_verify_NIST384_SHA384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha384Verify.rsp sha384)
#   set_tests_properties (test_ecdsa_verify_NIST384_SHA384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_ecdsa_verify_NIST384_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha512Verify.rsp sha512)
#   set_tests_properties (test_ecdsa_verify_NIST384_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif(AMCL_CHOICE STREQUAL "NIST384")

# if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8"))
#   message(STATUS "Run ${AMCL_CHOICE} RSA2048 Tests")
#   add_executable (test_rsa_sign test_rsa_sign.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_rsa_sign amcl_x509) 
#   # test
#   add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/2048/pkcs-vect.txt)
#   set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8"))

# if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
#   message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
#   add_executable (test_x509 test_x509.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_x509 amcl_x509) 
#   # test
#   add_test(NAME test_x509_NIST256_1 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/2048_P256/pkits-vect.txt)
#   set_tests_properties (test_x509_NIST256_1 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
#   add_test(NAME test_x509_NIST256_2 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/2048_P256/x509-vect.txt)
#   set_tests_properties (test_x509_NIST256_2 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

# if((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8"))
#   message(STATUS "Run ${AMCL_CHOICE} RSA3072 Tests")
#   add_executable (test_rsa_sign test_rsa_sign.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_rsa_sign amcl_x509)
#   # test
#   add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/3072/pkcs-vect.txt)
#   set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8"))

# if((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
#   message(STATUS "Run ${AMCL_CHOICE} RSA3072 Tests")
#   add_executable (test_x509 test_x509.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_x509 amcl_x509)
#   # test
#   add_test(NAME test_x509_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/3072_P384/x509-vect.txt)
#   set_tests_properties (test_x509_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

# if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16"))
#   message(STATUS "Run ${AMCL_CHOICE} RSA4096 Tests")
#   add_executable (test_rsa_sign test_rsa_sign.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_rsa_sign amcl_x509)
#   # test
#   add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/4096/pkcs-vect.txt)
#   set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16"))

# if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16") AND (BUILD_X509))
#   message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
#   add_executable (test_x509 test_x509.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_x509 amcl_x509) 
#   # test
#   add_test(NAME test_x509_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/4096/x509-vect.txt)
#   set_tests_properties (test_x509_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16") AND (BUILD_X509))

# if((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))
#   message(STATUS "Run ${AMCL_CHOICE} RSA2048 Tests")
#   add_executable (test_rsa_sign test_rsa_sign.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_rsa_sign amcl_x509) 
#   # test
#   add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/2048/pkcs-vect.txt)
#   set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))

# if((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "MONTGOMERY"))
#   message(STATUS "Run ${AMCL_CHOICE} ECDH Tests")
#   add_executable (test_ecdh test_ecdh.c)
#   # Link the executable to the libraries
#   target_link_libraries (test_ecdh amcl_ecc) 
#   # test
#   add_test(NAME test_ecdh COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/C25519/KAS_ECC_CDH_PrimitiveTest.txt)
#   set_tests_properties (test_ecdh PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
# endif((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "MONTGOMERY"))
