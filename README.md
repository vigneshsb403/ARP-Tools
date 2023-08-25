# ARP-Tools


## Requirements
make sure that you have installed lpcap.
or use the following code to do the same.
```
sudo apt-get install libpcap-dev
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
## ⚠️Note run the programs with sudo privilages.

Made with ❤️‍🔥 by [vigneshsb](https://vigneshsb.fun).
