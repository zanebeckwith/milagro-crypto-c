# This file sets the default build of the library and is run by typing "make"

# size of chunk in bits which is wordlength of computer = 16, 32 or 64.  (see arch.h)
AMCL_CHUNK:=64

# Current choice of Elliptic Curve (see amcl.h)
AMCL_CHOICE:=BN254_CX

# type of curve  (see amcl.h) 
AMCL_CURVETYPE:=WEIERSTRASS

# 2^n multiplier of BIGBITS to specify supported Finite Field size, 
# e.g 2048=256*2^3 where BIGBITS=256  (see amcl.h) 
AMCL_FFLEN:=8

# Build type Debug Release Coverage ASan Check CheckFull
CMAKE_BUILD_TYPE:=Release

# Install path
CMAKE_INSTALL_PATH:=/opt/amcl

# Run tests
AMCL_TEST:=ON

# Build Shared Libraries ON/OFF
AMCL_BUILD_SHARED_LIBS:=ON

# Build Python wrapper ON/OFF
AMCL_BUILD_PYTHON:=ON

# Build Golang wrapper ON/OFF
AMCL_BUILD_GO:=ON

# Build MPIN ON/OFF
AMCL_BUILD_MPIN:=ON

# Build WCC ON/OFF
AMCL_BUILD_WCC:=ON

# Build Doxygen ON/OFF
AMCL_BUILD_DOXYGEN:=ON

# Anonymous authentication for M-Pin Full ON/OFF
AMCL_USE_ANONYMOUS:=OFF

# Configure PIN 
AMCL_MAXPIN:=10000
AMCL_PBLEN:=14

# Print debug message for field reduction ON/OFF
DEBUG_REDUCE:=OFF

# Detect digit overflow ON/OFF
DEBUG_NORM:=OFF

# Architecture
CMAKE_C_FLAGS=

# Tool chain 
# options: ../../resources/cmake/mingw64-cross.cmake
#          ../../resources/cmake/mingw32-cross.cmake
CMAKE_TOOLCHAIN_FILE=
