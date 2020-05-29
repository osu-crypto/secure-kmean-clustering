Clone libOTe and Ivory-Runtime

Compile both libraries.

Cmake .

make -j

Execute the code: ./bin/frontend -r 0 & ./bin/frontend -r 1

git clone --recursive <url>
# install libraries for libOTe

git submodule update --init --recursive

cd libOTe/cryptoTools/thirdparty/linux

bash all.get


# build this project

## copy libOTe config (don't use SimplestOT)
`cp libOTe_config libOTe`

cmake  -G "Unix Makefiles"

make

# execute

./bin/frontend
