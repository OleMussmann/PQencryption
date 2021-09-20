HexEncoding makes the decryption process a bit slower. However, instead of a byte-string you get a proper hex-string. This might make the storage of the variables easier.


Salsa20 is faster than AES. A big part of the difference seems to be the random number generation for the initialization vector. Maybe we need to compare the speed of different sources of random numbers, especially if they only need to be pseudo-random. In the case of Salsa20, they only need to be different every time, not necessarily completely random. Maybe also for AES?  We should check that. Maybe we can also pre-generate a long string of random-numbers, so we don't have to call the generator every time we encrypt something.
