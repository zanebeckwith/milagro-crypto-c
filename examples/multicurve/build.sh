#!/usr/bin/env bash

BASE_DIR=$(pwd)

PROJ_DIR=$(pwd)/../..

AMCL_CHOICE=$(sed -nr '/AMCL_CHOICE:=(.*)$/{s//\1/;p}' ./config.mk)
AMCL_CURVETYPE=$(sed -nr '/AMCL_CURVETYPE:=(.*)$/{s//\1/;p}' ./config.mk)
AMCL_FFLEN=$(sed -nr '/AMCL_FFLEN:=(.*)$/{s//\1/;p}' ./config.mk)
echo "$AMCL_CHOICE"
echo "$AMCL_CURVETYPE"
echo "$AMCL_FFLEN"

CT="$(echo $AMCL_CURVETYPE | head -c 1)"
echo "$CT"

BUILDNAME=${AMCL_CHOICE}_${CT}_$AMCL_FFLEN
echo $BUILDNAME

#rm -rf target
#mkdir target
#rm -rf lib
#mkdir lib
#rm -rf include
#mkdir include
#rm -rf obj
#mkdir obj

function build_lib {
  buildname=${BUILDNAME,,}
  echo "Build ${buildname}"
  cp config.mk  $PROJ_DIR/config.mk
  cd $PROJ_DIR
  make
  cd $BASE_DIR
  cp -r $PROJ_DIR/target/default/ ./target/${buildname}
  cp target/${buildname}/src/libamcl_core.a  ./lib/

  echo "Build libamcl_curve_${buildname}"
  cp target/${buildname}/src/CMakeFiles/*.dir/*.o  ./obj
  rename .c.o _${buildname}.o ./obj/*
  ar qc ./lib/libamcl_curve_${buildname}.a  ./obj/big_${buildname}.o \
        ./obj/fp_${buildname}.o ./obj/ecp_${buildname}.o \
        ./obj/rom_${buildname}.o ./obj/ff_${buildname}.o \
        ./obj/version_${buildname}.o
  ranlib ./lib/libamcl_curve_${buildname}.a

  echo "Build libamcl_pairing_${buildname}.a"
  ar qc ./lib/libamcl_pairing_${buildname}.a  ./obj/fp2_${buildname}.o \
        ./obj/ecp2_${buildname}.o ./obj/fp4_${buildname}.o \
        ./obj/fp12_${buildname}.o ./obj/pair_${buildname}.o
  ranlib ./lib/libamcl_pairing_${buildname}.a

  echo "Build libamcl_mpin_${buildname}.a"
  ar qc ./lib/libamcl_mpin_${buildname}.a ./obj/mpin_${buildname}.o
  ranlib ./lib/libamcl_mpin_${buildname}.a

  echo "Build libamcl_ecc_${buildname}.a"
  ar qc ./lib/libamcl_ecc_${buildname}.a  ./obj/ecdh_${buildname}.o
  ranlib ./lib/libamcl_ecc_${buildname}.a

  echo "Build libamcl_rsa_${buildname}.a"
  ar qc ./lib/libamcl_rsa_${buildname}.a ./obj/rsa_${buildname}.o
  ranlib ./lib/libamcl_rsa_${buildname}.a

  echo "copy and rename headers"
  cp ./target/${buildname}/include/amcl.h ./include/amcl_${buildname}.h
  cp ./target/${buildname}/include/mpin.h ./include/mpin_${buildname}.h
  cp ./target/${buildname}/include/ecdh.h ./include/ecdh_${buildname}.h
  cp ./target/${buildname}/include/rsa.h ./include/rsa_${buildname}.h
  cp ./target/${buildname}/include/arch.h ./include/arch_${buildname}.h
  cp ./target/${buildname}/include/randapi.h ./include/randapi_${buildname}.h
}

function change_libamcl_mpin {
  libname=libamcl_mpin_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_empty=OCT_empty ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_GCM_add_cipher=GCM_add_cipher ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_GCM_add_header=GCM_add_header ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_GCM_add_plain=GCM_add_plain ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_GCM_finish=GCM_finish ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_GCM_init=GCM_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_hash=HASH256_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_init=HASH256_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_process=HASH256_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_hash=HASH384_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_init=HASH384_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_process=HASH384_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_hash=HASH512_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_init=HASH512_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_process=HASH512_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbyte=OCT_jbyte ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbytes=OCT_jbytes ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_joctet=OCT_joctet ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_time=time ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_RAND_byte=RAND_byte ./lib/${libname}
}

function change_libamcl_pairing {
  libname=libamcl_pairing_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_putchar=putchar ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_puts=puts ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_printf=printf ./lib/${libname}
}

function change_libamcl_curve {
  libname=libamcl_curve_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_RAND_byte=RAND_byte ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_putchar=putchar ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_puts=puts ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_printf=printf ./lib/${libname}
}

function change_libamcl_rsa {
  libname=libamcl_rsa_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_hash=HASH256_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_init=HASH256_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_process=HASH256_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_hash=HASH384_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_init=HASH384_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_process=HASH384_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_hash=HASH512_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_init=HASH512_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_process=HASH512_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_clear=OCT_clear ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_copy=OCT_copy ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_empty=OCT_empty ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbyte=OCT_jbyte ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbytes=OCT_jbytes ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_joctet=OCT_joctet ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_ncomp=OCT_ncomp ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_pad=OCT_pad ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_rand=OCT_rand ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_shl=OCT_shl ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_xor=OCT_xor ./lib/${libname}
}

function change_libamcl_ecc {
  libname=libamcl_ecc_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_AES_decrypt=AES_decrypt ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_AES_encrypt=AES_encrypt ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_AES_end=AES_end ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_AES_init=AES_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_hash=HASH256_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_init=HASH256_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH256_process=HASH256_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_hash=HASH384_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_init=HASH384_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH384_process=HASH384_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_hash=HASH512_hash ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_init=HASH512_init ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_HASH512_process=HASH512_process ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_chop=OCT_chop ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_clear=OCT_clear ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_comp=OCT_comp ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_copy=OCT_copy ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_empty=OCT_empty ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbyte=OCT_jbyte ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jbytes=OCT_jbytes ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_jint=OCT_jint ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_joctet=OCT_joctet ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_shl=OCT_shl ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_xor=OCT_xor ./lib/${libname}
  objcopy --redefine-sym ${BUILDNAME}_OCT_xorbyte=OCT_xorbyte ./lib/${libname}
}

function change_amcl_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to function names"
  sed -i "s/AMCL_H/${BUILDNAME}_AMCL_H/g" ./include/amcl_${buildname}.h
  sed -i "s/arch.h/arch_${buildname}.h/g" ./include/amcl_${buildname}.h
  sed -i "s/Modulus/${BUILDNAME}_Modulus/g" ./include/amcl_${buildname}.h
  sed -i "s/MConst/${BUILDNAME}_MConst/g" ./include/amcl_${buildname}.h
  sed -i "s/CURVE_/${BUILDNAME}_CURVE_/g" ./include/amcl_${buildname}.h
  sed -i "s/ECP/${BUILDNAME}_ECP/g" ./include/amcl_${buildname}.h
  sed -i "s/FP/${BUILDNAME}_FP/g" ./include/amcl_${buildname}.h
  sed -i "s/BIG/${BUILDNAME}_BIG/g" ./include/amcl_${buildname}.h
  sed -i "s/${BUILDNAME}_BIGBITS/BIGBITS/g" ./include/amcl_${buildname}.h
  sed -i "s/D${BUILDNAME}_BIG/DBIG/g" ./include/amcl_${buildname}.h
  sed -i "s/DBIG/${BUILDNAME}_DBIG/g" ./include/amcl_${buildname}.h
  sed -i "s/rsa_public_key/${BUILDNAME}_rsa_public_key/g" ./include/amcl_${buildname}.h
  sed -i "s/rsa_private_key/${BUILDNAME}_rsa_private_key/g" ./include/amcl_${buildname}.h
  sed -i "s/muladd/${BUILDNAME}_muladd/g" ./include/amcl_${buildname}.h
  sed -i "s/PAIR_/${BUILDNAME}_PAIR_/g" ./include/amcl_${buildname}.h
  sed -i "s/FF_/${BUILDNAME}_FF_/g" ./include/amcl_${buildname}.h
  sed -i "s/${BUILDNAME}_FF_BITS/FF_BITS/g" ./include/amcl_${buildname}.h
}

function change_randapi_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to randapi function names"
  sed -i "s/amcl.h/amcl_${buildname}.h/g" ./include/randapi_${buildname}.h
  sed -i "s/RANDOM_H/${BUILDNAME}_RANDOM_H/" ./include/randapi_${buildname}.h
}

function change_mpin_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to MPIN function names"
  sed -i "s/amcl.h/amcl_${buildname}.h/g" ./include/mpin_${buildname}.h
  sed -i "s/MPIN_/${BUILDNAME}_MPIN_/" ./include/mpin_${buildname}.h
}

function change_ecc_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to ECC function names"
  sed -i "s/ECDH_/${BUILDNAME}_ECDH_/g" ./include/ecdh_${buildname}.h
  sed -i "s/amcl.h/amcl_${buildname}.h/g" ./include/ecdh_${buildname}.h
  sed -i "s/HMAC/${BUILDNAME}_HMAC/g" ./include/ecdh_${buildname}.h
  sed -i "s/KDF2/${BUILDNAME}_KDF2/g" ./include/ecdh_${buildname}.h
  sed -i "s/PBKDF2/${BUILDNAME}_PBKDF2/g" ./include/ecdh_${buildname}.h
  sed -i "s/AES_CBC_IV0_ENCRYPT/${BUILDNAME}_AES_CBC_IV0_ENCRYPT/g" ./include/ecdh_${buildname}.h
  sed -i "s/AES_CBC_IV0_DECRYPT/${BUILDNAME}_AES_CBC_IV0_DECRYPT/g" ./include/ecdh_${buildname}.h
  sed -i "s/ECP_/${BUILDNAME}_ECP_/g" ./include/ecdh_${buildname}.h
  sed -i "s/ECPSP_DSA/${BUILDNAME}_ECPSP_DSA/g" ./include/ecdh_${buildname}.h
  sed -i "s/ECPVP_DSA/${BUILDNAME}_ECPVP_DSA/g" ./include/ecdh_${buildname}.h
}

function change_rsa_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to RSA function names"
  sed -i "s/RSA_H/${BUILDNAME}_RSA_H/g" ./include/rsa_${buildname}.h
  sed -i "s/amcl.h/amcl_${buildname}.h/g" ./include/rsa_${buildname}.h
  sed -i "s/RSA_KEY_PAIR/${BUILDNAME}_RSA_KEY_PAIR/g" ./include/rsa_${buildname}.h
  sed -i "s/rsa_public_key/${BUILDNAME}_rsa_public_key/g" ./include/amcl_${buildname}.h
  sed -i "s/rsa_private_key/${BUILDNAME}_rsa_private_key/g" ./include/amcl_${buildname}.h
  sed -i "s/PKCS15/${BUILDNAME}_PKCS15/g" ./include/rsa_${buildname}.h
  sed -i "s/OAEP_/${BUILDNAME}_OAEP_/g" ./include/rsa_${buildname}.h
  sed -i "s/RSA_ENCRYPT/${BUILDNAME}_RSA_ENCRYPT/g" ./include/rsa_${buildname}.h
  sed -i "s/RSA_DECRYPT/${BUILDNAME}_RSA_DECRYPT/g" ./include/rsa_${buildname}.h
  sed -i "s/RSA_PRIVATE_KEY_KILL/${BUILDNAME}_RSA_PRIVATE_KEY_KILL/g" ./include/rsa_${buildname}.h
}

build_lib
change_libamcl_mpin
change_libamcl_pairing
change_libamcl_curve
change_libamcl_rsa
change_libamcl_ecc
change_amcl_declaration
change_randapi_declaration
change_ecc_declaration
change_rsa_declaration
change_mpin_declaration


(setq minibuffer-max-depth nil)
