# ARP-Tools


## Requirements
make sure that you have installed lpcap.
or use the following code to do the same.
```
sudo apt-get install libpcap-dev
```

if you are on a mac
```
brew install libpcap
```

## Compiling
compile the lookup.c file with the following command.
```
gcc lookup.c -lpcap -o lookup
```

to comile the arpspoofdetector.c file use the following command
```
gcc arpspoofdetector.c -lpcap -o arpspoofdetector
```

to comile the sniffer.c file use the following command
```
gcc sniffer.c -lpcap -o sniffer
```

## Usage: 

### ⚠️Note run the programs with sudo privilages.

### Lookup
```
./lookup
```

### Arp spoof detector
```
sudo ./arpspoofdetector <interface>
```

### sniffer
```
sudo ./sniffer <interface> //make sure you change the port in the code
```
Made with ❤️‍🔥 by [vigneshsb](https://vigneshsb.fun).
