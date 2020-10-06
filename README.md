# pcap-simple-examples
simple examples for libpcap functions.
can NOT run on Windows.

### Platform
~~~
Linux kali 5.8.0-kali1-amd64 #1 SMP Debian 5.8.7-1kali1 (2020-09-14) x86_64 GNU/Linux
~~~

### Questions
~~~
cards using rtl8812au driver has different ioctl iw.u.freq.m values.
~~~

### Dependencies
~~~
sudo apt-get install valgrind libpcap-dev
~~~

### Run
~~~
make && script -c 'sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -s ./ex1 wlan2' log_ex1.txt
~~~