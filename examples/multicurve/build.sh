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

rm -rf target
mkdir target
rm -rf lib
mkdir lib
rm -rf include
mkdir include

function build_lib {
  buildname=${BUILDNAME,,}
  echo "Build ${prefix}"
  cp config.mk  $PROJ_DIR/config.mk
  cd $PROJ_DIR
  make
  cd $BASE_DIR
  cp -r $PROJ_DIR/target/default/ ./target/${buildname}
  cp target/${buildname}/src/libamcl_core.a  ./lib/
  cp target/${buildname}/src/libamcl_curve.a  ./lib/libamcl_curve_${buildname}.a
  cp target/${buildname}/src/libamcl_pairing.a  ./lib/libamcl_pairing_${buildname}.a
  cp target/${buildname}/src/libamcl_mpin.a  ./lib/libamcl_mpin_${buildname}.a
  cp ./target/${buildname}/include/amcl.h ./include/amcl_${buildname}.h
  cp ./target/${buildname}/include/mpin.h ./include/mpin_${buildname}.h
  cp ./target/${buildname}/include/arch.h ./include/arch.h
  cp ./target/${buildname}/include/randapi.h ./include/randapi.h
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
}

function change_libamcl_curve {
  libname=libamcl_curve_${BUILDNAME,,}.a
  echo "prefix symbol ${BUILDNAME}_ to ${libname}"
  objcopy --prefix-symbols=${BUILDNAME}_ ./lib/${libname}
}

function change_mpin_declaration {
  buildname=${BUILDNAME,,}
  echo "prefix ${BUILDNAME}_ to MPIN function names"
  sed -i "s/MPIN_/${BUILDNAME}_MPIN_/" ./include/mpin_${buildname}.h
}

build_lib
change_libamcl_mpin
change_libamcl_pairing
change_libamcl_curve
change_mpin_declaration

