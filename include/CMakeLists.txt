# AMCL header files

string(REGEX REPLACE "," ";" AMCL_CURVE ${AMCL_CURVE})
string(REGEX REPLACE "," ";" AMCL_RSA ${AMCL_RSA})

# Copy curve dependant header files
function(CURVE_SET tb tf tc nb base nbt m8 mt ct pf)
  set(bd "${tb}_${base}")
  set(fnameh "config_big_${bd}.h")
  file(READ "config_big_XXX.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "@NB@" ${nb} temph ${temph})
  string(REGEX REPLACE "@BASE@" ${base} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "config_field_${tf}.h")
  file(READ "config_field_YYY.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "YYY" ${tf} temph ${temph})
  string(REGEX REPLACE "@NBT@" ${nbt} temph ${temph})
  string(REGEX REPLACE "@M8@" ${m8} temph ${temph})
  string(REGEX REPLACE "@MT@" ${mt} temph ${temph})
  math(EXPR sh "${base} * (1 + ((8 * ${nb} - 1) / ${base})) - ${nbt}")
  if(sh GREATER '30')
    set(sh '30')
  endif(sh GREATER '30')
  MESSAGE( STATUS "SH is " ${sh} )
  string(REGEX REPLACE "@SH@" ${sh} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "config_curve_${tc}.h")
  file(READ "config_curve_ZZZ.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "YYY" ${tf} temph ${temph})
  string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
  string(REGEX REPLACE "@CT@" ${ct} temph ${temph})
  string(REGEX REPLACE "@PF@" ${pf} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "big_${bd}.h")
  file(READ "big_XXX.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "fp_${tf}.h")
  file(READ "fp_YYY.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "YYY" ${tf} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "ecp_${tf}.h")
  file(READ "ecp_ZZZ.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "YYY" ${tf} temph ${temph})
  string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "ecdh_${tc}.h")
  file(READ "ecdh_ZZZ.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "YYY" ${tf} temph ${temph})
  string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  if(NOT(${pf} STREQUAL "NOT"))

    set(fnameh "fp2_${tc}.h")
    file(READ "fp2_YYY.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

    set(fnameh "fp4_${tc}.h")
    file(READ "fp4_YYY.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

    set(fnameh "fp12_${tc}.h")
    file(READ "fp12_YYY.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

    set(fnameh "ecp2_${tc}.h")
    file(READ "ecp2_ZZZ.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

    set(fnameh "pair_${tc}.h")
    file(READ "pair_ZZZ.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

    set(fnameh "mpin_${tc}.h")
    file(READ "mpin_ZZZ.h" temph)
    string(REGEX REPLACE "XXX" ${bd} temph ${temph})
    string(REGEX REPLACE "YYY" ${tf} temph ${temph})
    string(REGEX REPLACE "ZZZ" ${tc} temph ${temph})
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})
  endif(NOT(${pf} STREQUAL "NOT"))

endfunction(CURVE_SET tb tf tc nb base nbt m8 mt ct pf)

# Copy rsa dependant header files
function(RSA_SET tb tff nb base ml)
  set(bd "${tb}_${base}")
  set(fnameh "config_big_${bd}.h")
  file(READ "config_big_XXX.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "@NB@" ${nb} temph ${temph})
  string(REGEX REPLACE "@BASE@" ${base} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "config_ff_${tff}.h")
  file(READ "config_ff_WWW.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "WWW" ${tff} temph ${temph})
  string(REGEX REPLACE "@ML@" ${ml} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "big_${bd}.h")
  file(READ "big_XXX.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "ff_${tff}.h")
  file(READ "ff_WWW.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "WWW" ${tff} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

  set(fnameh "rsa_${tff}.h")
  file(READ "rsa_WWW.h" temph)
  string(REGEX REPLACE "XXX" ${bd} temph ${temph})
  string(REGEX REPLACE "WWW" ${tff} temph ${temph})
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${fnameh}" ${temph})

endfunction(RSA_SET tb tff nb base ml)

set(COMMON_HEADERS
	amcl.h
	x509.h
	randapi.h)

# Copy common header files to binary include directory
file(COPY ${COMMON_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# Copy arch.h
set(fnameh "ecp2_${tc}.h")
file(READ "arch.h" temph)
string(REGEX REPLACE "@WL@" ${AMCL_CHUNK} temph ${temph})
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/arch.h" ${temph})

foreach(CURVE ${AMCL_CURVE})
  if(CURVE STREQUAL "ED25519")
    CURVE_SET("256" "25519" "ED25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "C25519")
    CURVE_SET("256" "25519" "C25519" "32" "56" "255" "5" "PSEUDO_MERSENNE" "MONTGOMERY" "NOT")
  elseif(CURVE STREQUAL "NIST256")
    CURVE_SET("256" "NIST256" "NIST256" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "BRAINPOOL")
    CURVE_SET("256" "BRAINPOOL" "BRAINPOOL" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "ANSSI")
    CURVE_SET("256" "ANSSI" "ANSSI" "32" "56" "256" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "HIFIVE")
    CURVE_SET("336" "HIFIVE" "HIFIVE" "42" "60" "336" "5" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "GOLDILOCKS")
    CURVE_SET("448" "GOLDILOCKS" "GOLDILOCKS" "56" "58" "448" "7" "GENERALISED_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "NIST384")
    CURVE_SET("384" "NIST384" "NIST384" "48" "56" "384" "7" "NOT_SPECIAL" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "C41417")
    CURVE_SET("416" "C41417" "C41417" "52" "60" "414" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "NIST521")
    CURVE_SET("528" "NIST521" "NIST521" "66" "60" "521" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "NIST521")
    CURVE_SET("256" "NIST521" "NUMS256W" "32" "56" "256" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "NUMS256E")
    CURVE_SET("256" "256PME" "NUMS256E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "NUMS384W")
    CURVE_SET("384" "384PM" "NUMS384W" "32" "56" "254" "3" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "NUMS384E")
    CURVE_SET("384" "384PM" "NUMS384E" "32" "56" "256" "3" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "NUMS512W")
    CURVE_SET("512" "512PM" "NUMS512W" "32" "56" "256" "7" "PSEUDO_MERSENNE" "WEIERSTRASS" "NOT")
  elseif(CURVE STREQUAL "NUMS512E")
    CURVE_SET("512" "512PM" "NUMS512E" "32" "56" "256" "7" "PSEUDO_MERSENNE" "EDWARDS" "NOT")
  elseif(CURVE STREQUAL "BN254")
    CURVE_SET("256" "BN254" "BN254" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
  elseif(CURVE STREQUAL "BN254CX")
    CURVE_SET("256" "BN254CX" "BN254CX" "32" "56" "254" "3" "NOT_SPECIAL" "WEIERSTRASS" "BN")
  elseif(CURVE STREQUAL "BLS383")
    CURVE_SET("384" "BLS383" "BLS383" "48" "56" "383" "3" "NOT_SPECIAL" "WEIERSTRASS" "BLS")
  endif(CURVE STREQUAL "ED25519")
endforeach(CURVE)

foreach(RSA ${AMCL_RSA})
  if(RSA STREQUAL "2048")
	  RSA_SET("1024" "2048" "128" "58" "2")
  elseif(RSA STREQUAL "3072")
	  RSA_SET("384" "3072" "48" "56" "8")
  elseif(RSA STREQUAL "4096")
	  RSA_SET("512" "4096" "64" "60" "8")
  endif(RSA STREQUAL "2048")
endforeach(RSA)

# if(BUILD_MPIN)
#   set(AMCL_HEADERS ${AMCL_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/mpin.h)
# endif(BUILD_MPIN)

# if(BUILD_WCC)
#   set(COPY_HEADERS ${COPY_HEADERS} wcc.h)
#   set(AMCL_HEADERS ${AMCL_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/wcc.h)
# endif(BUILD_WCC)

# # Copy header files to binary include directory
# file(COPY ${COPY_HEADERS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

# # Copy header files for testing before installation
# file(COPY ${AMCL_HEADERS} DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go/")

# install (DIRECTORY DESTINATION include DIRECTORY_PERMISSIONS
#         OWNER_WRITE OWNER_READ OWNER_EXECUTE
#         GROUP_WRITE GROUP_READ
#         WORLD_WRITE WORLD_READ WORLD_EXECUTE)

# install (FILES ${AMCL_HEADERS} DESTINATION include PERMISSIONS
#         OWNER_WRITE OWNER_READ OWNER_EXECUTE
#         GROUP_READ GROUP_EXECUTE
#         WORLD_READ WORLD_EXECUTE)