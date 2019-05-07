This is an implementation of rfc3484 default destination address selection for uclibc and uclibc-ng in getaddrinfo api. The code is migrated from glibc getaddrinfo.
Also handles gai.conf file.



How to add it to your current uclibc-ng ?

Create a patch with the already present getaddrinfo.c and resolv.c in uclibc(-ng)/libc/inet/

for eg: 
    patch getaddrinfo.c uclibc/libc/inet/getaddrinfo.c > my.patch
    patch resolv.c uclibc/libc/inet/resolv.c > my2.patch
    cp my.patch toolchain/uClibc/
    cp my2.patch toolchain/uClibc/
