# This file sets the default build of the library and is run by typing "make"

# size of chunk in bits which is wordlength of computer = 16, 32 or 64.  (see arch.h)
AMCL_CHUNK:=64

# Current choice of Elliptic Curve NIST256 C25519 ED25519 BRAINPOOL ANSSI NUMS256E NUMS256W NUMS384E NUMS384W NUMS512E NUMS512W HIFIVE GOLDILOCKS NIST384 C41417 NIST521 BN254 BN254CX BLS383
AMCL_CURVE:=BLS383,BN254,BN254CX,ED25519,GOLDILOCKS,NIST256

# RSA security level: 2048 3072 4096
AMCL_RSA:=2048,3072,4096

# Build type Debug Release Coverage ASan Check CheckFull
CMAKE_BUILD_TYPE:=Release

# Install path
CMAKE_INSTALL_PATH:=/opt/amcl

# Run tests
AMCL_TEST:=ON

# Build Shared Libraries ON/OFF
AMCL_BUILD_SHARED_LIBS:=ON

# Build Python wrapper ON/OFF
AMCL_BUILD_PYTHON:=OFF

# Build Golang wrapper ON/OFF
AMCL_BUILD_GO:=OFF

# Build MPIN ON/OFF
AMCL_BUILD_MPIN:=ON

# Build WCC ON/OFF
AMCL_BUILD_WCC:=ON

# Build Doxygen ON/OFF
AMCL_BUILD_DOXYGEN:=OFF

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
