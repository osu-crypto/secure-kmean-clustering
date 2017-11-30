# install libraries for libOTe
git submodule update --init --recursive
cd libOTe/cryptoTools/thirdparty/linux
bash all.get


# build this project
cmake  -G "Unix Makefiles"
make

# execute
./