#!/usr/bin/env bash

BUILDNAME1=BN254_CX_W_8
echo "Build $BUILDNAME1"
buildname1=${BUILDNAME1,,}

rm -rf build
mkdir build

cp testmpin.c ./build/testmpin_${buildname1}.c
sed -i "s/randapi.h/randapi_${buildname1}.h/g" ./build/testmpin_${buildname1}.c
sed -i "s/mpin/mpin_${buildname1}/g" ./build/testmpin_${buildname1}.c
sed -i "s/MPIN_/${BUILDNAME1}_MPIN_/" ./build/testmpin_${buildname1}.c
echo "gcc -std=c99 -g ./build/testmpin_${buildname1}.c -I../include -L../lib -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} -lamcl_core -o ./build/testmpin_${buildname1}"
gcc -std=c99 -g ./build/testmpin_${buildname1}.c -I../include -L../lib -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} -lamcl_core -o ./build/testmpin_${buildname1}

BUILDNAME2=BLS383_W_8
echo $BUILDNAME2
buildname2=${BUILDNAME2,,}

cp testmpin.c ./build/testmpin_${buildname2}.c
sed -i "s/randapi.h/randapi_${buildname2}.h/g" ./build/testmpin_${buildname2}.c
sed -i "s/mpin/mpin_${buildname2}/g" ./build/testmpin_${buildname2}.c
sed -i "s/MPIN_/${BUILDNAME2}_MPIN_/" ./build/testmpin_${buildname2}.c
echo "gcc -std=c99 -g ./build/testmpin_${buildname2}.c -I../include -L../lib -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} -lamcl_core -o ./build/testmpin_${buildname2}"
gcc -std=c99 -g ./build/testmpin_${buildname2}.c -I../include -L../lib -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} -lamcl_core -o ./build/testmpin_${buildname2}


cp testmpin_multi_curves.c ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/build1/${buildname1}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/BUILD1/${BUILDNAME1}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/build2/${buildname2}/g" ./build/testmpin_${buildname1}_${buildname2}.c
sed -i "s/BUILD2/${BUILDNAME2}/g" ./build/testmpin_${buildname1}_${buildname2}.c
gcc -std=c99 -g ./build/testmpin_${buildname1}_${buildname2}.c -I../include -L../lib \
    -lamcl_mpin_${buildname1} -lamcl_pairing_${buildname1} -lamcl_curve_${buildname1} \
    -lamcl_core -lamcl_mpin_${buildname2} -lamcl_pairing_${buildname2} -lamcl_curve_${buildname2} \
    -o ./build/testmpin_${buildname1}_${buildname2}
