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