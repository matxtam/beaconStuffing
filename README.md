
## Install Dependencies
```bash
# install libpcap
sudo apt-get install libpcap-dev

# install cmake (required by libwifi)
sudo apt-get install cmake

# install libwifi
git clone https://github.com/libwifi/libwifi.git
cd libwifi
make
mkdir build
cd build
cmake ..
make
sudo make install
cd ../..
```

## Run the Files
Run sender
``` bash
make send
sudo ./send.o
```
Run sniffer
```bash
make sniff
sudo ./sniff.o
```

