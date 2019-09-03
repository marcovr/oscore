# OSCORE - Object Security for Constrained RESTful Environments
[WIP] Proof-of-concept implementation of OSCORE including the EDHOC security profile.

## Dependencies
### TinyCBOR
```
git clone https://github.com/intel/tinycbor.git && cd tinycbor
make
sudo make install
```

### wolfSSL
```
git clone https://github.com/wolfSSL/wolfssl.git && cd wolfssl
sh autogen.sh
./configure --enable-aesccm --enable-hkdf C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP"
make
sudo make install
```

### libcoap
```
git clone https://github.com/obgm/libcoap.git && cd libcoap
./autogen.sh
./configure --disable-manpages
make
sudo make install
```

### Catch2
Used to run test cases.
```
sudo apt install catch
```

## To update the dynamic library list
```
sudo ldconfig
```

## Building
```
git clone --recursive https://github.com/marcovr/oscore.git && cd oscore
cmake
make
```

## Running tests
```
./src/tests
```