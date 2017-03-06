#!/usr/bin/env bash

BASE_DIR=$(pwd)

BUILD_DIR=$(pwd)/..

rm -rf build
mkdir build

# Curve 1

AMCL_CHOICE=$(sed -nr '/AMCL_CHOICE:=(.*)$/{s//\1/;p}' ./config_curve1.mk)
AMCL_CURVETYPE=$(sed -nr '/AMCL_CURVETYPE:=(.*)$/{s//\1/;p}' ./config_curve1.mk)
AMCL_FFLEN=$(sed -nr '/AMCL_FFLEN:=(.*)$/{s//\1/;p}' ./config_curve1.mk)
CT="$(echo $AMCL_CURVETYPE | head -c 1)"

BUILDNAME1=${AMCL_CHOICE}_${CT}_$AMCL_FFLEN
buildname1=${BUILDNAME1,,}
echo "Build $BUILDNAME1"

cp ./config_curve1.mk  ${BUILD_DIR}/config.mk
cd ${BUILD_DIR}
rm -rf target
mkdir target
rm -rf lib
mkdir lib
rm -rf include
mkdir include
rm -rf obj
mkdir obj
cp ./amclAPI.h ./include/amcl.h
./buildlib.sh
cd ${BASE_DIR}

cp testmpin.c ./build/testmpin_${buildname1}.c
sed -i "s/mpin/mpin_${buildname1}/g" ./build/testmpin_${buildname1}.c
sed -i "s/MPIN_/${BUILDNAME1}_MPIN_/" ./build/testmpin_${buildname1}.c
sed -i "s/PGS/${BUILDNAME1}_PGS/g" ./build/testmpin_${buildname1}.c
sed -i "s/PFS/${BUILDNAME1}_PFS/g" ./build/testmpin_${buildname1}.c 
sed -i "s/PAS/${BUILDNAME1}_PAS/g" ./build/testmpin_${buildname1}.c
sed -i "s/HASH_TYPE_MPIN/${BUILDNAME1}_HASH_TYPE_MPIN/g" ./build/testmpin_${buildname1}.c
echo "gcc -std=c99 -g ./build/testmpin_${buildname1}.c -I../include -L../lib -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} -lamcl_core -o ./build/testmpin_${buildname1}"
gcc -std=c99 -g ./build/testmpin_${buildname1}.c -I../include -L../lib -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} -lamcl_core -o ./build/testmpin_${buildname1}

# Curve 2

AMCL_CHOICE=$(sed -nr '/AMCL_CHOICE:=(.*)$/{s//\1/;p}' ./config_curve2.mk)
AMCL_CURVETYPE=$(sed -nr '/AMCL_CURVETYPE:=(.*)$/{s//\1/;p}' ./config_curve2.mk)
AMCL_FFLEN=$(sed -nr '/AMCL_FFLEN:=(.*)$/{s//\1/;p}' ./config_curve2.mk)
CT="$(echo $AMCL_CURVETYPE | head -c 1)"

BUILDNAME2=${AMCL_CHOICE}_${CT}_$AMCL_FFLEN
buildname2=${BUILDNAME2,,}
echo "Build $BUILDNAME2"

cp ./config_curve2.mk  ${BUILD_DIR}/config.mk
cd ${BUILD_DIR}
MODBYTES=48 ./buildlib.sh
cd ${BASE_DIR}

cp testmpin.c ./build/testmpin_${buildname2}.c
sed -i "s/mpin/mpin_${buildname2}/g" ./build/testmpin_${buildname2}.c
sed -i "s/MPIN_/${BUILDNAME2}_MPIN_/" ./build/testmpin_${buildname2}.c
sed -i "s/PGS/${BUILDNAME2}_PGS/g" ./build/testmpin_${buildname2}.c
sed -i "s/PFS/${BUILDNAME2}_PFS/g" ./build/testmpin_${buildname2}.c
sed -i "s/PAS/${BUILDNAME2}_PAS/g" ./build/testmpin_${buildname2}.c
sed -i "s/HASH_TYPE_MPIN/${BUILDNAME2}_HASH_TYPE_MPIN/g" ./build/testmpin_${buildname2}.c
echo "gcc -std=c99 -g ./build/testmpin_${buildname2}.c -I../include -L../lib -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} -lamcl_core -o ./build/testmpin_${buildname2}"
gcc -std=c99 -g ./build/testmpin_${buildname2}.c -I../include -L../lib -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} -lamcl_core -o ./build/testmpin_${buildname2}

# Both curves

cp testmpin_multi_curves.c ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/build1/${buildname1}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/BUILD1/${BUILDNAME1}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/build2/${buildname2}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/BUILD2/${BUILDNAME2}/g" ./build/testmpin_${buildname1}_${buildname2}.c
gcc -std=c99 -g ./build/testmpin_${buildname1}_${buildname2}.c -I../include -L../lib \
    -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} \
    -lamcl_core -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} \
    -o ./build/testmpin_${buildname1}_${buildname2}
