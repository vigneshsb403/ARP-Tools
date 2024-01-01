# ARP-Tools

<p align="center">
<a href="https://twitter.com/sbvignesh"><img src="https://img.shields.io/twitter/follow/sbvignesh.svg?logo=twitter"></a>
<a href="https://github.com/vigneshsb403/ARP-Tools/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
</p>

<p align="center">
  <a href="#requirements">Requirements</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#compiling">Compiling</a>
</p>

# Requirements
make sure that you have installed lpcap.
or use the following code to do the same.
```
sudo apt-get install libpcap-dev
```

if you are on a mac and have home brew
```
brew install libpcap
```

# Installation
```
git clone https://github.com/vigneshsb403/ARP-Tools.git
```

# Compiling
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

# Usage 

> [!NOTE]\
> Run the programs with sudo privilages.

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

*********

Made with ❤️‍🔥 by [vigneshsb](https://vigneshsb.fun).
