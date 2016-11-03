# Tests

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src)
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include )

#define macro to simplify adding tests
macro (do_test arg result)
  add_test (${arg} ${TARGET_SYSTEM_EMULATOR} ${arg}${CMAKE_EXECUTABLE_SUFFIX})
  set_tests_properties (${arg}
    PROPERTIES PASS_REGULAR_EXPRESSION ${result}
    )
endmacro ()

# smoke tests  
add_executable (test_rsa test_rsa.c)
add_executable (test_ecc test_ecc.c)
add_executable (test_version test_version.c)
add_executable (test_BIG_consistency test_big_consistency.c)
add_executable (test_octet_consistency test_octet_consistency.c)
# Link the executable to the libraries
target_link_libraries (test_rsa rsa) 
target_link_libraries (test_ecc ecdh) 
target_link_libraries (test_version amcl) 
target_link_libraries (test_octet_consistency amcl)
target_link_libraries (test_BIG_consistency amcl )
# run tests
do_test (test_rsa "SUCCESS")
do_test (test_ecc "SUCCESS")
do_test (test_version "Version: ${AMCL_VERSION_MAJOR}.${AMCL_VERSION_MINOR}.${AMCL_VERSION_PATCH}")
do_test (test_octet_consistency "SUCCESS")
do_test (test_BIG_consistency "SUCCESS")

# Arithmetics tests BIG
message(STATUS "Run ${AMCL_CHOICE} Arithmetics Tests")
add_executable (test_BIG_arithmetics test_big_arithmetics.c)
# Link the executable to the libraries
target_link_libraries (test_BIG_arithmetics amcl)
# test
add_test(NAME test_BIG_arithmetics COMMAND ${TARGET_SYSTEM_EMULATOR} test_BIG_arithmetics ${PROJECT_SOURCE_DIR}/testVectors/big/test_vector_big.txt)
set_tests_properties (test_BIG_arithmetics PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)

# Arithmetics test FP for pairing-friendly cuves
if(((AMCL_CHOICE STREQUAL "BN454") OR (AMCL_CHOICE STREQUAL "BN254_T") OR  (AMCL_CHOICE STREQUAL "BN254_T2") OR (AMCL_CHOICE STREQUAL "BN254_CX") OR (AMCL_CHOICE STREQUAL "BN646")
OR (AMCL_CHOICE STREQUAL "BLS455") OR (AMCL_CHOICE STREQUAL "MF254") OR (AMCL_CHOICE STREQUAL "NIST256") OR (AMCL_CHOICE STREQUAL "BRAINPOOL") OR (AMCL_CHOICE STREQUAL "ANSSI") 
OR (AMCL_CHOICE STREQUAL "MF256") OR (AMCL_CHOICE STREQUAL "NIST384")) AND (AMCL_CURVETYPE STREQUAL "WEIERSTRASS"))

  add_executable (test_FP_arithmetics test_fp_arithmetics.c)
  add_test(NAME test_FP_arithmetics COMMAND ${TARGET_SYSTEM_EMULATOR} test_FP_arithmetics ${PROJECT_SOURCE_DIR}/testVectors/fp/test_vector_${AMCL_CHOICE}.txt)
  target_link_libraries (test_FP_arithmetics amcl)

endif(((AMCL_CHOICE STREQUAL "BN454") OR (AMCL_CHOICE STREQUAL "BN254_T") OR  (AMCL_CHOICE STREQUAL "BN254_T2") OR (AMCL_CHOICE STREQUAL "BN254_CX") OR (AMCL_CHOICE STREQUAL "BN646")
OR (AMCL_CHOICE STREQUAL "BLS455") OR (AMCL_CHOICE STREQUAL "MF254") OR (AMCL_CHOICE STREQUAL "NIST256") OR (AMCL_CHOICE STREQUAL "BRAINPOOL") OR (AMCL_CHOICE STREQUAL "ANSSI")
OR (AMCL_CHOICE STREQUAL "MF256") OR (AMCL_CHOICE STREQUAL "NIST384")) AND (AMCL_CURVETYPE STREQUAL "WEIERSTRASS"))

# curve independent tests
add_executable (test_hash test_hash.c)
add_executable (test_gcm_encrypt test_gcm_encrypt.c)
add_executable (test_gcm_decrypt test_gcm_decrypt.c)
add_executable (test_aes_encrypt test_aes_encrypt.c)
add_executable (test_aes_decrypt test_aes_decrypt.c)
# Link the executable to the libraries
target_link_libraries (test_hash amcl) 
target_link_libraries (test_gcm_encrypt amcl) 
target_link_libraries (test_gcm_decrypt amcl) 
target_link_libraries (test_aes_encrypt amcl) 
target_link_libraries (test_aes_decrypt amcl)
 
# hash tests
add_test(NAME test_hash_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_hash ${PROJECT_SOURCE_DIR}/testVectors/sha/256/SHA256ShortMsg.rsp sha256)
set_tests_properties (test_hash_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_hash_512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_hash ${PROJECT_SOURCE_DIR}/testVectors/sha/512/SHA512ShortMsg.rsp sha512)
set_tests_properties (test_hash_512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)

# AES-GCM tests
add_test(NAME test_gcm_encrypt_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_gcm_encrypt ${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmEncryptExtIV128.rsp)
set_tests_properties (test_gcm_encrypt_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_gcm_encrypt_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_gcm_encrypt ${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmEncryptExtIV256.rsp)
set_tests_properties (test_gcm_encrypt_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_gcm_decrypt_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_gcm_decrypt ${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmDecrypt128.rsp)
set_tests_properties (test_gcm_decrypt_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_gcm_decrypt_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_gcm_decrypt ${PROJECT_SOURCE_DIR}/testVectors/gcm/gcmDecrypt256.rsp)
set_tests_properties (test_gcm_decrypt_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)

# AES tests
add_test(NAME test_aes_encrypt_ECB_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT128.rsp  ECB)
set_tests_properties (test_aes_encrypt_ECB_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_encrypt_ECB_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT256.rsp  ECB)
set_tests_properties (test_aes_encrypt_ECB_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_encrypt_CBC_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT128.rsp  CBC)
set_tests_properties (test_aes_encrypt_CBC_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_encrypt_CBC_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT256.rsp  CBC)
set_tests_properties (test_aes_encrypt_CBC_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_encrypt_CTR_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL128.rsp  CTR)
set_tests_properties (test_aes_encrypt_CTR_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_encrypt_CTR_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_encrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL256.rsp  CTR)
set_tests_properties (test_aes_encrypt_CTR_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)

add_test(NAME test_aes_decrypt_ECB_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT128.rsp  ECB)
set_tests_properties (test_aes_decrypt_ECB_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_decrypt_ECB_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/ECBMMT256.rsp  ECB)
set_tests_properties (test_aes_decrypt_ECB_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_decrypt_CBC_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT128.rsp  CBC)
set_tests_properties (test_aes_decrypt_CBC_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_decrypt_CBC_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/CBCMMT256.rsp  CBC)
set_tests_properties (test_aes_decrypt_CBC_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_decrypt_CTR_128 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL128.rsp  CTR)
set_tests_properties (test_aes_decrypt_CTR_128 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
add_test(NAME test_aes_decrypt_CTR_256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_aes_decrypt ${PROJECT_SOURCE_DIR}/testVectors/aes/amcl_CTRMCL256.rsp  CTR)
set_tests_properties (test_aes_decrypt_CTR_256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)

if(BUILD_MPIN)
  add_executable (test_mpin test_mpin.c)
  add_executable (test_mpin_sign test_mpin_sign.c)
  add_executable (test_mpin_good test_mpin_good.c)
  add_executable (test_mpin_bad_pin test_mpin_bad_pin.c)
  add_executable (test_mpin_bad_token test_mpin_bad_token.c)
  add_executable (test_mpin_expired_tp test_mpin_expired_tp.c)
  add_executable (test_mpin_tp test_mpin_tp.c)
  add_executable (test_mpin_random test_mpin_random.c)
  add_executable (test_mpinfull test_mpinfull.c)
  add_executable (test_mpinfull_onepass test_mpinfull_onepass.c)
  add_executable (test_mpinfull_random test_mpinfull_random.c)
  add_executable (test_utils test_utils.c)
  # Link the executable to the libraries
  target_link_libraries (test_mpin mpin) 
  target_link_libraries (test_mpin_sign mpin) 
  target_link_libraries (test_mpin_good mpin) 
  target_link_libraries (test_mpin_bad_pin mpin) 
  target_link_libraries (test_mpin_bad_token mpin) 
  target_link_libraries (test_mpin_expired_tp mpin) 
  target_link_libraries (test_mpin_tp mpin) 
  target_link_libraries (test_mpin_random mpin) 
  target_link_libraries (test_mpinfull mpin) 
  target_link_libraries (test_mpinfull_onepass mpin) 
  target_link_libraries (test_mpinfull_random mpin) 
  target_link_libraries (test_utils mpin) 
  # tests
  do_test (test_mpin "SUCCESS Error Code 0")
  do_test (test_mpin_sign "TEST PASSED")
  do_test (test_mpin_good "SUCCESS Error Code 0")
  do_test (test_mpin_bad_pin "FAILURE")
  do_test (test_mpin_bad_token "FAILURE Invalid Token Error Code -19")
  do_test (test_mpin_expired_tp "FAILURE Invalid Token Error Code -19")
  do_test (test_mpin_tp "Iteration ${MPIN_TIME_PERMIT_TESTS} SUCCESS Error Code 0")
  do_test (test_mpin_random "Iteration ${MPIN_RANDOM_TESTS} SUCCESS Error Code 0")
  do_test (test_mpinfull "SUCCESS")
  do_test (test_mpinfull_onepass "SUCCESS")
  do_test (test_mpinfull_random "Iteration ${MPIN_RANDOM_TESTS} SUCCESS")
  do_test (test_utils "SUCCESS")
endif(BUILD_MPIN)

if(BUILD_WCC)
  add_executable (test_wcc_gcm test_wcc_gcm.c)
  add_executable (test_wcc test_wcc.c)
  add_executable (test_wcc_random test_wcc_random.c)
  # Link the executable to the libraries
  target_link_libraries (test_wcc_gcm wcc) 
  target_link_libraries (test_wcc wcc) 
  target_link_libraries (test_wcc_random wcc) 
  # tests  
  do_test (test_wcc_gcm "SUCCESS")
  do_test (test_wcc "SUCCESS")
  do_test (test_wcc_random "SUCCESS")
endif(BUILD_WCC)  

if(AMCL_CHOICE STREQUAL "NIST256")
  message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
  add_executable (test_ecdsa_sign test_ecdsa_sign.c)
  add_executable (test_ecdsa_verify test_ecdsa_verify.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  target_link_libraries (test_ecdsa_keypair ecdh) 
  target_link_libraries (test_ecdsa_sign ecdh) 
  target_link_libraries (test_ecdsa_verify ecdh) 
  # test
  add_test(NAME test_ecdh_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-256/KAS_ECC_CDH_PrimitiveTest.txt)
  set_tests_properties (test_ecdh_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_keypair_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/KeyPair.rsp)
  set_tests_properties (test_ecdsa_keypair_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST256_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha256Sign.rsp sha256)
  set_tests_properties (test_ecdsa_sign_NIST256_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST256_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha512Sign.rsp sha512)
  set_tests_properties (test_ecdsa_sign_NIST256_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST256_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha256Verify.rsp sha256)
  set_tests_properties (test_ecdsa_verify_NIST256_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST256_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-256/sha512Verify.rsp sha512)
  set_tests_properties (test_ecdsa_verify_NIST256_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif(AMCL_CHOICE STREQUAL "NIST256")

if(AMCL_CHOICE STREQUAL "NIST521")
  message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
  add_executable (test_ecdsa_sign test_ecdsa_sign.c)
  add_executable (test_ecdsa_verify test_ecdsa_verify.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  target_link_libraries (test_ecdsa_keypair ecdh) 
  target_link_libraries (test_ecdsa_sign ecdh) 
  target_link_libraries (test_ecdsa_verify ecdh)
  # test
  add_test(NAME test_ecdh_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-521/KAS_ECC_CDH_PrimitiveTest.txt)
  set_tests_properties (test_ecdh_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_keypair_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/KeyPair.rsp)
  set_tests_properties (test_ecdsa_keypair_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST521_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha256Sign.rsp sha256)
  set_tests_properties (test_ecdsa_sign_NIST521_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST521_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha512Sign.rsp sha512)
  set_tests_properties (test_ecdsa_sign_NIST521_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST521_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha256Verify.rsp sha256)
  set_tests_properties (test_ecdsa_verify_NIST521_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST521_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-521/sha512Verify.rsp sha512)
  set_tests_properties (test_ecdsa_verify_NIST521_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif(AMCL_CHOICE STREQUAL "NIST521")

if((AMCL_CHOICE STREQUAL "NIST521")  AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
  message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
  add_executable (test_x509 test_x509.c)
  # Link the executable to the libraries
  target_link_libraries (test_x509 x509)
  # test
  add_test(NAME test_x509_NIST521 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/P521/x509-vect.txt)
  set_tests_properties (test_x509_NIST521 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST521")  AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

if(AMCL_CHOICE STREQUAL "NIST384")
  message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
  add_executable (test_ecdsa_sign test_ecdsa_sign.c)
  add_executable (test_ecdsa_verify test_ecdsa_verify.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  target_link_libraries (test_ecdsa_keypair ecdh) 
  target_link_libraries (test_ecdsa_sign ecdh) 
  target_link_libraries (test_ecdsa_verify ecdh)
  # test
  add_test(NAME test_ecdh_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/P-384/KAS_ECC_CDH_PrimitiveTest.txt)
  set_tests_properties (test_ecdh_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_keypair_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/KeyPair.rsp)
  set_tests_properties (test_ecdsa_keypair_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST384_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha256Sign.rsp sha256)
  set_tests_properties (test_ecdsa_sign_NIST384_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST384_SHA384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha384Sign.rsp sha384)
  set_tests_properties (test_ecdsa_sign_NIST384_SHA384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_NIST384_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha512Sign.rsp sha512)
  set_tests_properties (test_ecdsa_sign_NIST384_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST384_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha256Verify.rsp sha256)
  set_tests_properties (test_ecdsa_verify_NIST384_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST384_SHA384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha384Verify.rsp sha384)
  set_tests_properties (test_ecdsa_verify_NIST384_SHA384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_NIST384_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/P-384/sha512Verify.rsp sha512)
  set_tests_properties (test_ecdsa_verify_NIST384_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif(AMCL_CHOICE STREQUAL "NIST384")

if((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))
  message(STATUS "Run ${AMCL_CHOICE} ${AMCL_CURVETYPE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
  add_executable (test_ecdsa_sign test_ecdsa_sign.c)
  add_executable (test_ecdsa_verify test_ecdsa_verify.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  target_link_libraries (test_ecdsa_keypair ecdh) 
  target_link_libraries (test_ecdsa_sign ecdh) 
  target_link_libraries (test_ecdsa_verify ecdh) 
  # test
  add_test(NAME test_ecdh_C25519 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/C25519/amcl_ecdh.txt)
  set_tests_properties (test_ecdh_C25519 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_keypair_C25519 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/C25519/amcl_ecdsa_sha256.txt)
  set_tests_properties (test_ecdsa_keypair_C25519 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_C25519_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/C25519/amcl_ecdsa_sha256.txt sha256)
  set_tests_properties (test_ecdsa_sign_C25519_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_C25519_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/C25519/amcl_ecdsa_sha512.txt sha512)
  set_tests_properties (test_ecdsa_sign_C25519_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_C25519_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/C25519/amcl_ecdsa_sha256.txt sha256)
  set_tests_properties (test_ecdsa_verify_C25519_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_C25519_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/C25519/amcl_ecdsa_sha512.txt sha512)
  set_tests_properties (test_ecdsa_verify_C25519_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))

if((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_CURVETYPE STREQUAL "MONTGOMERY"))
  message(STATUS "Run ${AMCL_CHOICE} ${AMCL_CURVETYPE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  # test
  add_test(NAME test_ecdh_C25519_MONT COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/C25519/amcl_ecdh_mont.txt)
  set_tests_properties (test_ecdh_C25519_MONT PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_CURVETYPE STREQUAL "MONTGOMERY"))

if(AMCL_CHOICE STREQUAL "GOLDILOCKS")
  message(STATUS "Run ${AMCL_CHOICE} ECC Tests")
  add_executable (test_ecdh test_ecdh.c)
  add_executable (test_ecdsa_keypair test_ecdsa_keypair.c)
  add_executable (test_ecdsa_sign test_ecdsa_sign.c)
  add_executable (test_ecdsa_verify test_ecdsa_verify.c)
  # Link the executable to the libraries
  target_link_libraries (test_ecdh ecdh) 
  target_link_libraries (test_ecdsa_keypair ecdh) 
  target_link_libraries (test_ecdsa_sign ecdh) 
  target_link_libraries (test_ecdsa_verify ecdh) 
  # test
  add_test(NAME test_ecdh_GOLDILOCKS COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdh ${PROJECT_SOURCE_DIR}/testVectors/ecdh/GOLDILOCKS/amcl_ecdh.txt)
  set_tests_properties (test_ecdh_GOLDILOCKS PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_keypair_GOLDILOCKS COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_keypair ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/GOLDILOCKS/amcl_ecdsa_sha256.txt)
  set_tests_properties (test_ecdsa_keypair_GOLDILOCKS PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_GOLDILOCKS_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/GOLDILOCKS/amcl_ecdsa_sha256.txt sha256)
  set_tests_properties (test_ecdsa_sign_GOLDILOCKS_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_sign_GOLDILOCKS_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_sign ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/GOLDILOCKS/amcl_ecdsa_sha512.txt sha512)
  set_tests_properties (test_ecdsa_sign_GOLDILOCKS_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_GOLDILOCKS_SHA256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/GOLDILOCKS/amcl_ecdsa_sha256.txt sha256)
  set_tests_properties (test_ecdsa_verify_GOLDILOCKS_SHA256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_ecdsa_verify_GOLDILOCKS_SHA512 COMMAND ${TARGET_SYSTEM_EMULATOR} test_ecdsa_verify ${PROJECT_SOURCE_DIR}/testVectors/ecdsa/GOLDILOCKS/amcl_ecdsa_sha512.txt sha512)
  set_tests_properties (test_ecdsa_verify_GOLDILOCKS_SHA512 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif(AMCL_CHOICE STREQUAL "GOLDILOCKS")

if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8"))
  message(STATUS "Run ${AMCL_CHOICE} RSA2048 Tests")
  add_executable (test_rsa_sign test_rsa_sign.c)
  # Link the executable to the libraries
  target_link_libraries (test_rsa_sign x509) 
  # test
  add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/2048/pkcs-vect.txt)
  set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8"))

if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
  message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
  add_executable (test_x509 test_x509.c)
  # Link the executable to the libraries
  target_link_libraries (test_x509 x509) 
  # test
  add_test(NAME test_x509_NIST256_1 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/2048_P256/pkits-vect.txt)
  set_tests_properties (test_x509_NIST256_1 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
  add_test(NAME test_x509_NIST256_2 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/2048_P256/x509-vect.txt)
  set_tests_properties (test_x509_NIST256_2 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

if((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8"))
  message(STATUS "Run ${AMCL_CHOICE} RSA3072 Tests")
  add_executable (test_rsa_sign test_rsa_sign.c)
  # Link the executable to the libraries
  target_link_libraries (test_rsa_sign x509)
  # test
  add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/3072/pkcs-vect.txt)
  set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8"))

if((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))
  message(STATUS "Run ${AMCL_CHOICE} RSA3072 Tests")
  add_executable (test_x509 test_x509.c)
  # Link the executable to the libraries
  target_link_libraries (test_x509 x509)
  # test
  add_test(NAME test_x509_NIST384 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/3072_P384/x509-vect.txt)
  set_tests_properties (test_x509_NIST384 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST384") AND (AMCL_FFLEN STREQUAL "8") AND (BUILD_X509))

if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16"))
  message(STATUS "Run ${AMCL_CHOICE} RSA4096 Tests")
  add_executable (test_rsa_sign test_rsa_sign.c)
  # Link the executable to the libraries
  target_link_libraries (test_rsa_sign x509)
  # test
  add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/4096/pkcs-vect.txt)
  set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16"))

if((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16") AND (BUILD_X509))
  message(STATUS "Run ${AMCL_CHOICE} x509 Tests")
  add_executable (test_x509 test_x509.c)
  # Link the executable to the libraries
  target_link_libraries (test_x509 x509) 
  # test
  add_test(NAME test_x509_NIST256 COMMAND ${TARGET_SYSTEM_EMULATOR} test_x509 ${PROJECT_SOURCE_DIR}/testVectors/x509/4096/x509-vect.txt)
  set_tests_properties (test_x509_NIST256 PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "NIST256") AND (AMCL_FFLEN STREQUAL "16") AND (BUILD_X509))

if((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))
  message(STATUS "Run ${AMCL_CHOICE} RSA2048 Tests")
  add_executable (test_rsa_sign test_rsa_sign.c)
  # Link the executable to the libraries
  target_link_libraries (test_rsa_sign x509) 
  # test
  add_test(NAME test_rsa_sign COMMAND ${TARGET_SYSTEM_EMULATOR} test_rsa_sign ${PROJECT_SOURCE_DIR}/testVectors/rsa/2048/pkcs-vect.txt)
  set_tests_properties (test_rsa_sign PROPERTIES PASS_REGULAR_EXPRESSION SUCCESS)
endif((AMCL_CHOICE STREQUAL "C25519") AND (AMCL_FFLEN STREQUAL "8") AND (AMCL_CURVETYPE STREQUAL "EDWARDS"))

