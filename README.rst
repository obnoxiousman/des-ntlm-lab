###################
 DES in C
###################
C implementation of Data Encryption Standard algorithm.

Did you come here from https://obman.pikapod.net/books/active-directory/page/understanding-ntlm

Overview
========
This is a reimplementation of https://github.com/tarequeh/DES

Compilation & Installation
==========================
This implementation has only been tested on Unix platform. But you may be able to compile/ run it on Windows.

1. Make sure des.c, des.h and run_des.c are in the same directory 
2. Compile using: gcc -O3 des.c run_des.c -o run_des.o   

Usage
=====
Say we want to encrypt/ decrypt a file named /home/user/sample.txt

1. Simply see the encryption of password `Password!`::

    run_des.o 
2. You can change the hard coded value of `nthash` in `run_des.c` ::

###################
 NTLMv2.py
###################

Python implementation of ntlmv2 to understand the computation of NTLMv2 response
