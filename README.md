# Practical Privacy-Preserving K-means Clustering
This is the implementation of our [PETS 2020](https://petsymposium.org/cfp20.php)  paper: **Practical Privacy-Preserving K-means Clustering**[[ePrint](https://eprint.iacr.org/2019/1158). 

Evaluating on a single server (`2 36-cores Intel Xeon CPU E5-2699 v3 @ 2.30GHz and 256GB of RAM`) with a single thread per party,  our scheme requires  `18` minutes to cluster 100,000 data samples into 2 groups.

## Installations
### Clone project
```
git clone --recursive git@github.com:osu-crypto/SpOT-PSI.git
```

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`libOTe`](https://github.com/osu-crypto/libOTe), and [`Ivory-Runtime`](https://github.com/nitrieu/Ivory-Runtime/tree/e4bb8350e6ad6fdfa5a51994fff1db86d25527a0). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries: 
  * For building boost, miracl and libOTe, please follow the more instructions at [`libOTe`](https://github.com/osu-crypto/libOTe). A quick try for linux: `cd libOTe/cryptoTools/thirdparty/linux/`, `bash all.get`, `cd` back to `libOTe`, `cmake .` and then `make -j`
  * For Ivory-Runtime, `cd Ivory-Runtime/thirdparty/linux`, and `bash ./ntl.get`. Then, you can run `cmake -G"Unix Makefiles"` in Ivory-Runtime folder, and then `make -j`   

NOTE: if you meet problem with NTL, try to do the following and read [`Building and using NTL with GMP`](https://www.shoup.net/ntl/doc/tour-gmp.html). If you see an error message `cmd.exe not found`, try to install https://www.nasm.us/

### Building the Project
After recursively cloning project from git `git clone --recursive `, 
##### Windows:
1. build cryptoTools,libOTe, Ivory-Runtime, libCluster, frontend projects in order.
2. run frontend project
 
##### Linux:
1. make (requirements: `CMake`, `Make`, `g++` or similar)
2. for test:
	./bin/frontend.exe 


## Running the code

##### 1. Unit test:
	./bin/frontend.exe -t
	
#### 2. Simulation: 
Using two terminals, (For now, the kmean parameters are hardcoding in the main.cpp file, we will add more flags soon)

On the terminal 1, run:

	./bin/frontend -r 0
	
On the terminal 2, run:
	
	./bin/frontend -r 1
 
		
## Help
For any questions on building or running the library, please contact [`Ni Trieu`](http://people.oregonstate.edu/~trieun/) at trieun at oregonstate dot edu
