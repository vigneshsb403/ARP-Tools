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
## ⚠️Note run the programs with sudo privilages.

Made with ❤️‍🔥 by [vigneshsb](https://vigneshsb.fun).
