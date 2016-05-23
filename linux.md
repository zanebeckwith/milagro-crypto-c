<h2>Software dependencies</h2>

CMake is required to build the library and can usually be installed from
the operating system package manager.

<ul type="disc">
  <li>sudo apt-get install cmake</li>
</ul>
If not, then you can download it from www.cmake.org

You also need some additional dev tools:

<ul type="disc">
  <li>sudo apt-get install -y git build-essential python-dev python-pip libffi-dev</li>
</ul>

The C Foreign Function Interface for Python <a href="https://cffi.readthedocs.org/en/latest/">CFFI</a> module
is also required if you wish to use the Python module.

<ul type="disc">
  <li>sudo pip install cffi</li>
</ul>

In order to build the documentation <a href="http://www.stack.nl/~dimitri/doxygen/">doxygen</a> is required.

<h2>Build Instructions</h2>

<p>NOTE: The default build is for 32 bit machines</p>

<ol type="disc">
  <li>git clone https://github.com/miracl/milagro-crypto</li>
  <li>cd milagro-crypto</li>
  <li>mkdir release</li>
  <li>cd release</li>
  <li>cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl ..</li>
  <li>export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./</li>
  <li>make</li>
  <li>make test</li>
  <li>sudo make install<br />
  <em>On Debian/Ubuntu machine instead of executing the "sudo make install" it is possible to execute the "sudo checkinstall" to build and install a DEB package.</em></li>
</ol>

Now you can set the path to where libs and python package are installed:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./:/opt/amcl/lib
    export PYTHONPATH=/usr/lib/python2.7/dist-packages


<p>NOTE: The build can be configured by setting flags on the command line, for example:</p>

<ol type="disc">
  <li>cmake -DWORD_LENGTH=64 ..</li>
  <li>cmake -D CMAKE_INSTALL_PREFIX=/opt/amcl -D USE_ANONYMOUS=on -D WORD_LENGTH=64 -D BUILD_WCC=on ..</li>
</ol>

<h2>Uninstall software</h2>

<ul type="disc">
  <li>sudo make uninstall</li>
</ul>

<h2>Building an installer</h2>

<p>After having built the libraries you can build a binary installer and a source distribution by running this command</p>

<ul type="disc">
  <li>make package</li>
</ul>


