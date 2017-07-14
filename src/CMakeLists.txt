# Create AMCL library

# Add the binary tree directory to the search path for linking and include files
link_directories( ${CMAKE_CURRENT_BINARY_DIR} )
include_directories (${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_BINARY_DIR}/include )

# create new file replacing curve dependant parameters
function(CURVE_SRC_SET tb tf tc nb base nbt m8 mt ct pf)
  set(bd "${tb}_${base}")
             
  set(fnamec "big_${bd}.c")
  file(READ "big_XXX.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  set(SOURCES_CURVE_${tc}
    ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

  set(fnamec "fp_${tf}.c")
  file(READ "fp_YYY.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  file(COPY "rom_field_${tf}.c" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  set(SOURCES_CURVE_${tc} ${SOURCES_CURVE_${tc}}
    ${CMAKE_CURRENT_BINARY_DIR}/${fnamec}
    ${CMAKE_CURRENT_BINARY_DIR}/rom_field_${tf}.c)

  set(fnamec "ecp_${tc}.c")
  file(READ "ecp_ZZZ.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
  string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  set(SOURCES_CURVE_${tc} ${SOURCES_CURVE_${tc}}
    ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

  set(fnamec "ecdh_${tc}.c")
  file(READ "ecdh_ZZZ.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
  string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  file(COPY "rom_curve_${tc}.c" DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  set(SOURCES_CURVE_${tc} ${SOURCES_CURVE_${tc}}
    ${CMAKE_CURRENT_BINARY_DIR}/${fnamec}
    ${CMAKE_CURRENT_BINARY_DIR}/rom_curve_${tc}.c)

  message(STATUS "Build libamcl_curve_${tc}")
  add_library(amcl_curve_${tc} ${LIB_TYPE} ${SOURCES_CURVE_${tc}})
  target_link_libraries (amcl_curve_${tc} amcl_core)

  if(NOT(${pf} STREQUAL "NOT") AND (BUILD_MPIN))

    set(fnamec "fp2_${tc}.c")
    file(READ "fp2_YYY.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    set(fnamec "fp4_${tc}.c")
    file(READ "fp4_YYY.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
    ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    set(fnamec "fp12_${tc}.c")
    file(READ "fp12_YYY.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    set(fnamec "ecp2_${tc}.c")
    file(READ "ecp2_ZZZ.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    set(fnamec "pair_${tc}.c")
    file(READ "pair_ZZZ.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    set(fnamec "mpin_${tc}.c")
    file(READ "mpin_ZZZ.c" tempc)
    string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
    string(REGEX REPLACE "YYY" ${tf} tempc "${tempc}")
    string(REGEX REPLACE "ZZZ" ${tc} tempc "${tempc}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
    set(SOURCES_PAIRING_${tc}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

    message(STATUS "Build libamcl_pairing_${tc}")
    add_library(amcl_pairing_${tc} ${LIB_TYPE} ${SOURCES_PAIRING_${tc}})
    target_link_libraries (amcl_pairing_${tc} amcl_curve_${tc} amcl_core)
  endif(NOT(${pf} STREQUAL "NOT") AND (BUILD_MPIN))

endfunction(CURVE_SRC_SET tb tf tc nb base nbt m8 mt ct pf)

function(RSA_SRC_SET tb tff nb base ml)
  
  set(bd "${tb}_${base}")
  set(fnamec "big_${bd}.c")
  file(READ "big_XXX.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  set(SOURCES_RSA_${tff}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

  set(fnamec "ff_${tff}.c")
  file(READ "ff_WWW.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  set(SOURCES_RSA_${tff}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

  set(fnamec "rsa_${tff}.c")
  file(READ "rsa_WWW.c" tempc)
  string(REGEX REPLACE "XXX" ${bd} tempc "${tempc}")
  string(REGEX REPLACE "WWW" ${tff} tempc "${tempc}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnamec}" "${tempc}")
  set(SOURCES_RSA_${tff}
      ${CMAKE_CURRENT_BINARY_DIR}/${fnamec})

  message(STATUS "Build libamcl_rsa_${tff}")
  add_library(amcl_rsa_${tff} ${LIB_TYPE} ${SOURCES_RSA_${tff}})
  target_link_libraries (amcl_rsa_${tff} amcl_core)

endfunction(RSA_SRC_SET tb tff nb base ml)

set(SOURCES_AMCL_CORE
hash.c
rand.c
randapi.c
aes.c
gcm.c
oct.c
utils.c
ecdh_support.c
rsa_support.c)
# mpin_support (if MPIN_BUILD)
# version.c)

# Copy common header files to binary include directory
file(COPY ${SOURCES_AMCL_CORE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(DEST_SOURCES_AMCL_CORE
${CMAKE_CURRENT_BINARY_DIR}/hash.c
${CMAKE_CURRENT_BINARY_DIR}/rand.c
${CMAKE_CURRENT_BINARY_DIR}/randapi.c
${CMAKE_CURRENT_BINARY_DIR}/aes.c
${CMAKE_CURRENT_BINARY_DIR}/gcm.c
${CMAKE_CURRENT_BINARY_DIR}/oct.c
${CMAKE_CURRENT_BINARY_DIR}/utils.c
${CMAKE_CURRENT_BINARY_DIR}/ecdh_support.c
${CMAKE_CURRENT_BINARY_DIR}/rsa_support.c
)
# mpin_support (if MPIN_BUILD)
# version.c

message(STATUS "Build libamcl_core")
add_library(amcl_core ${LIB_TYPE} ${DEST_SOURCES_AMCL_CORE})
target_link_libraries (amcl_core)

string(REGEX REPLACE "," ";" AMCL_CURVE ${AMCL_CURVE})
string(REGEX REPLACE "," ";" AMCL_RSA ${AMCL_RSA})

foreach(CURVE ${AMCL_CURVE})
  if(AMCL_CHUNK STREQUAL "64")
    if(CURVE STREQUAL "ED25519")
        CURVE_SRC_SET("256" "25519" "ED25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "C25519")
        CURVE_SRC_SET("256" "25519" "C25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "MONTGOMERY" "NOT")
    elseif(CURVE STREQUAL "NIST256")
        CURVE_SRC_SET("256" "NIST256" "NIST256" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "BRAINPOOL")
        CURVE_SRC_SET("256" "BRAINPOOL" "BRAINPOOL" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "ANSSI")
        CURVE_SRC_SET("256" "ANSSI" "ANSSI" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "HIFIVE")
        CURVE_SRC_SET("336" "HIFIVE" "HIFIVE" "42" "60" "336" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "GOLDILOCKS")
        CURVE_SRC_SET("448" "GOLDILOCKS" "GOLDILOCKS" "56" "58" "448" "7" "GENERALISED_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST384")
        CURVE_SRC_SET("384" "NIST384" "NIST384" "48" "56" "384" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "C41417")
        CURVE_SRC_SET("416" "C41417" "C41417" "52" "60" "414" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_SRC_SET("528" "NIST521" "NIST521" "66" "60" "521" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_SRC_SET("256" "NIST521" "NUMS256W" "32" "56" "256" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS256E")
        CURVE_SRC_SET("256" "256PME" "NUMS256E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS384W")
        CURVE_SRC_SET("384" "384PM" "NUMS384W" "32" "56" "254" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS384E")
        CURVE_SRC_SET("384" "384PM" "NUMS384E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS512W")
        CURVE_SRC_SET("512" "512PM" "NUMS512W" "32" "56" "256" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS512E")
        CURVE_SRC_SET("512" "512PM" "NUMS512E" "32" "56" "256" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "BN254")
        CURVE_SRC_SET("256" "BN254" "BN254" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BN254CX")
        CURVE_SRC_SET("256" "BN254CX" "BN254CX" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BLS383")
        CURVE_SRC_SET("384" "BLS383" "BLS383" "48" "56" "383" "3" "NOT_SPECIAL" "WEIERSTRASS" "BLS")
    endif(CURVE STREQUAL "ED25519")
  elseif(AMCL_CHUNK STREQUAL "32")
    if(CURVE STREQUAL "ED25519")
        CURVE_SRC_SET("256" "25519" "ED25519" "32" "29" "255" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "C25519")
        CURVE_SRC_SET("256" "25519" "C25519" "32" "29" "255" "5" "PSEUDO_MERSENNE" "MONTGOMERY" "NOT")
    elseif(CURVE STREQUAL "NIST256")
        CURVE_SRC_SET("256" "NIST256" "NIST256" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "BRAINPOOL")
        CURVE_SRC_SET("256" "BRAINPOOL" "BRAINPOOL" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "ANSSI")
        CURVE_SRC_SET("256" "ANSSI" "ANSSI" "32" "28" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "HIFIVE")
        CURVE_SRC_SET("336" "HIFIVE" "HIFIVE" "42" "29" "336" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "GOLDILOCKS")
        CURVE_SRC_SET("448" "GOLDILOCKS" "GOLDILOCKS" "56" "29" "448" "7" "GENERALISED_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST384")
        CURVE_SRC_SET("384" "NIST384" "NIST384" "48" "29" "384" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "C41417")
        CURVE_SRC_SET("416" "C41417" "C41417" "52" "29" "414" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_SRC_SET("528" "NIST521" "NIST521" "66" "28" "521" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NIST521")
        CURVE_SRC_SET("256" "256PMW" "NUMS256W" "32" "28" "256" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS256E")
        CURVE_SRC_SET("256" "256PME" "NUMS256E" "32" "29" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS384W")
        CURVE_SRC_SET("384" "384PM" "NUMS384W" "32" "29" "254" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS384E")
        CURVE_SRC_SET("384" "384PM" "NUMS384E" "32" "29" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "NUMS512W")
        CURVE_SRC_SET("512" "512PM" "NUMS512W" "32" "29" "256" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
    elseif(CURVE STREQUAL "NUMS512E")
        CURVE_SRC_SET("512" "512PM" "NUMS512E" "32" "29" "256" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
    elseif(CURVE STREQUAL "BN254")
        CURVE_SRC_SET("256" "BN254" "BN254" "32" "28" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BN254CX")
        CURVE_SRC_SET("256" "BN254CX" "BN254CX" "32" "28" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
    elseif(CURVE STREQUAL "BLS383")
        CURVE_SRC_SET("384" "BLS383" "BLS383" "48" "29" "383" "3" "NOT_SPECIAL" "WEIERSTRASS" "BLS")
    endif(CURVE STREQUAL "ED25519")
  endif(AMCL_CHUNK STREQUAL "64")
endforeach(CURVE)

foreach(RSA ${AMCL_RSA})
  if(RSA STREQUAL "2048")
    RSA_SRC_SET("1024" "2048" "128" "58" "2")
  elseif(RSA STREQUAL "3072")
    RSA_SRC_SET("384" "3072" "48" "56" "8")
  elseif(RSA STREQUAL "4096")
    RSA_SRC_SET("512" "4096" "64" "60" "8")
  endif(RSA STREQUAL "2048")
endforeach(RSA)

# if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
#     message(STATUS "Copy libs to test for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.dll" "${PROJECT_BINARY_DIR}/test/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dll" "${PROJECT_BINARY_DIR}/test/")

#     add_custom_command(
#                 TARGET amcl_ecc
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_ecc.dll" "${PROJECT_BINARY_DIR}/test/")

#     add_custom_command(
#                 TARGET amcl_rsa
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_rsa.dll" "${PROJECT_BINARY_DIR}/test/")

#     if(BUILD_X509)
#     add_custom_command(
#                 TARGET amcl_x509
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_x509.dll" "${PROJECT_BINARY_DIR}/test/")
#     endif(BUILD_X509)

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.dll" "${PROJECT_BINARY_DIR}/test/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.dll" "${PROJECT_BINARY_DIR}/test/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.dll" "${PROJECT_BINARY_DIR}/test/")
#     endif(BUILD_WCC)

# endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

# # Copy built libs to wrappers/python to allow testing without
# # having to install the libs.
# if (BUILD_PYTHON AND BUILD_SHARED_LIBS)

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#     message(STATUS "Copy libs to wrappers/python for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.so" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.so" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.so" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.so" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.so" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_WCC)  

#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
#     message(STATUS "Copy libs to wrappers/python for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.dll" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_WCC)

#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

#     message(STATUS "Copy libs to wrappers/python for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_curve
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.dylib" "${PROJECT_BINARY_DIR}/wrappers/python/")
#     endif(BUILD_WCC)  


#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")


# endif (BUILD_PYTHON AND BUILD_SHARED_LIBS)


# # Copy built libs to wrappers/go to allow testing without
# # having to install the libs.
# if (BUILD_GO AND BUILD_SHARED_LIBS)

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#     message(STATUS "Copy libs to wrappers/go for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.so" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_rsa
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_rsa.so" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_ecc
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_ecc.so" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.so" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.so" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.so" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.so" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_WCC)  

#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
#     message(STATUS "Copy libs to wrappers/go for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_rsa
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_rsa.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_ecc
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_ecc.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.dll" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_WCC)

#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

#     message(STATUS "Copy libs to wrappers/go for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_rsa
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_rsa.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_ecc
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_ecc.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     if(BUILD_MPIN OR BUILD_WCC)
#         add_custom_command(
#                     TARGET amcl_pairing
#                     POST_BUILD
#                     COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.dylib" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_WCC)  


#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")


# endif (BUILD_GO AND BUILD_SHARED_LIBS)

# # Static build
# if (BUILD_GO AND NOT BUILD_SHARED_LIBS)

#   if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

#     message(STATUS "Copy libs to wrappers/go for testing")
#     add_custom_command(
#                 TARGET amcl_core
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_core.a" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_rsa
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_rsa.a" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_ecc
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_ecc.a" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     add_custom_command(
#                 TARGET amcl_curve
#                 POST_BUILD
#                 COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_curve.a" "${PROJECT_BINARY_DIR}/wrappers/go/")

#     if(BUILD_MPIN OR BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_pairing
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_pairing.a" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN OR BUILD_WCC)

#     if(BUILD_MPIN)
#       add_custom_command(
#                   TARGET amcl_mpin
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_mpin.a" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_MPIN)

#     if(BUILD_WCC)
#       add_custom_command(
#                   TARGET amcl_wcc
#                   POST_BUILD
#                   COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/libamcl_wcc.a" "${PROJECT_BINARY_DIR}/wrappers/go/")
#     endif(BUILD_WCC)  

#   endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

# endif (BUILD_GO AND NOT BUILD_SHARED_LIBS)

# # Install libs
# install(DIRECTORY DESTINATION lib DIRECTORY_PERMISSIONS
#         OWNER_WRITE OWNER_READ OWNER_EXECUTE
#         GROUP_WRITE GROUP_READ
#         WORLD_WRITE WORLD_READ WORLD_EXECUTE)

# set(INSTALL_LIBS amcl_core amcl_curve amcl_rsa amcl_ecc)

# if(BUILD_X509)
#   set(INSTALL_LIBS ${INSTALL_LIBS} amcl_x509)
# endif(BUILD_X509)

# if(BUILD_MPIN)
#   set(INSTALL_LIBS ${INSTALL_LIBS} amcl_mpin amcl_pairing )
# endif(BUILD_MPIN)

# if(BUILD_WCC)
#   set(INSTALL_LIBS ${INSTALL_LIBS} amcl_wcc amcl_pairing )
# endif(BUILD_WCC)

# install (TARGETS ${INSTALL_LIBS} DESTINATION lib PERMISSIONS
#         OWNER_WRITE OWNER_READ OWNER_EXECUTE
#         GROUP_READ GROUP_EXECUTE
#         WORLD_READ WORLD_EXECUTE)

