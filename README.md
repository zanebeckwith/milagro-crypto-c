# AMCL

*AMCL - Apache Milagro Crypto Library*


* **category**:    Library
* **copyright**:   2016 The Apache Software Foundation
* **license**:     Apache License Version 2.0, January 2004 (see LICENSE file)
* **link**:        https://github.com/tecnickcom/milagro-crypto-c
* **introduction**: [AMCL.pdf](doc/AMCL.pdf)

## Description

*AMCL - Apache Milagro Crypto Library*

AMCL is a standards compliant C crypto library with no external dependencies, specifically designed to support the Internet of Things.
For a detailed explanation about this library please read: [doc/AMCL.pdf](doc/AMCL.pdf)

NOTE: This product includes software developed at [The Apache Software Foundation](http://www.apache.org/).


## Software Dependencies

In order to build this library, the following packages are required:

* [CMake](ttp://www.cmake.org) is required to build the source code.;
* [CFFI](https://cffi.readthedocs.org/en/release-0.8/), the C Foreign Function Interface for Python is required in order to execute tests; 
* [Doxygen](http://doxygen.org) is required to build the source code documentation.


The above packages can be installed in different ways, depending on the Operating System used:

* **Debian/Ubuntu Linux**


    sudo apt-get install -y git cmake build-essential python python-dev python-pip libffi-dev doxygen doxygen-latex
    sudo pip install cffi
    
* **RedHat/CentOS/Fedora Linux**


    sudo yum groupinstall "Development Tools" "Development Libraries"
    sudo yum install -y git cmake python libpython-devel python-pip libffi-devel doxygen doxygen-latex
    sudo pip install cffi

* **MacOs**


    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew install cmake
    brew install pkg-config libffi
    sudo pip install cffi
    brew install doxygen

* **Windows**
    * Minimalist GNU for Windows [MinGW](http://www.mingw.org) provides the tool set used to build the library and should be installed
    * When the MinGW installer starts select the **mingw32-base** and **mingw32-gcc-g++** components
    * From the menu select *"Installation"* &rarr; *"Apply Changes"*, then click *"Apply"*
    * Finally add *C:\MinGW\bin* to the PATH variable
    * pip install cffi
    * install CMake following the instructions on http://www.cmake.org
    * install Doxygen following the instructions on http://www.doxygen.org


## Build Instructions

NOTE: The default build is for 32 bit machines


### Linux and Mac

    git clone https://github.com/miracl/milagro-crypto-c
    cd milagro-crypto-c
    mkdir -p target/release
    cd target/release
    cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl ../..
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./
    make
    make test
    make doc
    sudo make install

On Debian/Ubuntu machine instead of executing the *"sudo make install"* command it is possible to execute *"sudo checkinstall"* to build and install a DEB package.

Now you can set the path to where libs and python package are installed:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./:/opt/amcl/lib
    export PYTHONPATH=/usr/lib/python2.7/dist-packages

NOTE: The build can be configured by setting flags on the command line, for example:

* cmake -DWORD_LENGTH=64 ../..
* cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D USE_ANONYMOUS=on -D WORD_LENGTH=64 -D BUILD_WCC=on ../..

#### Uninstall software

    sudo make uninstall

#### Building an installer (only for Linux)

After having built the libraries you can build a binary installer and a source distribution by running this command

    make package


### Windows

Start a command prompt as an administrator

    git clone https://github.com/miracl/milagro-crypto-c
    cd milagro-crypto-c
    mkdir -p target/release
    cd target/release
    cmake -G "MinGW Makefiles" ../..
    mingw32-make
    mingw32-make test
    mingw32-make doc
    mingw32-make install

Post install append the PATH system variable to point to the install ./lib:

*My Computer -> Properties -> Advanced > Environment Variables*

The build can be configured using by setting flags on the command line i.e.

    cmake -G "MinGW Makefiles" -DWORD_LENGTH=64 ..

#### Uninstall software

    mingw32-make uninstall

#### Building an installer

After having built the libraries you can build a Windows installer using this command

    sudo mingw32-make package

In order for this to work NSSI has to have been installed
