# song-wagner-perrig

This is the implementation of the final scheme described in the Practical Techniques for Searches on Encrypted Data.
It is a simple, command-line application developed in Python 2.7.

## Usage

Put the input files in ```/raw``` and run the script. The script applies encryption algorithm and put the encrypted files 
in ```/ciphertext```. To search, enter a keyword and search algorithm looks into the encrypted files and gives the result back.

There are sample input files and the respective encrypted files. To start, take a look into ```/raw/``` to get keywords. 

```
$ python scheme.py 

Enter a word to search: tarantula
Not present in input0.enc
Present in input1.enc

Enter a word to search: rooster
Present in input0.enc
Not present in input1.enc

Enter a word to search: this
Present in input0.enc
Present in input1.enc

Enter a word to search: lion
Not present in input0.enc
Not present in input1.enc

Enter a word to search:  // Press Ctrl+D to exit
Quitting...

$ 
```

This work was a part of the master thesis from TU Dresden under the supervision of Dr. Josef Spillner and Martin Beck.

##[Practical Techniques for Searches on Encrypted Data](http://www.cs.berkeley.edu/~dawnsong/papers/se.pdf)

by Dawn Xiaodong Song, David Wagner, and Adrian Perrig.

In this paper, the authors develop a set of algorithms that allow searches 
over encrypted data. These algorithms provide a linear search (O(n)) for each
document and introduce relatively little space overhead. Proofs of the security
of their model are also included which show that the server the data is hosted
on “cannot learn anything about the plaintext given only the ciphertext”.
