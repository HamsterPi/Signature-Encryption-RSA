Assignment 2: Digital Signature Using RSA

The aim of this assignment is to implement a digital signature using RSA. Before the digital signature can be implemented, you will need to set up an appropriate public/private RSA key pair. This should be done as follows:

Generate two distinct 512-bit probable primes p and q
Calculate the product of these two primes n = pq
Calculate the Euler totient function phi(n)
You will be using an encryption exponent e = 65537, so you will need to ensure that this is relatively prime to phi(n). If it is not, go back to step 1 and generate new values for p and q
Compute the value for the decryption exponent d, which is the multiplicative inverse of e (mod phi(n)). This should use your own implementation of the extended Euclidean GCD algorithm to calculate the inverse rather than using a library method for this purpose.
You should then write code to implement a decryption method which calculates h(m)d (mod n) for message digest h(m). You should use your own implementation of the Chinese Remainder Theorem to calculate this more efficiently; this can also make use of your multiplicative inverse implementation.

You will then digitally sign the digest of an input binary file using your RSA decryption method. The 256-bit digest will be produced using SHA-256. Note that, for the purpose of this assignment, no randomness or redundancy should be added to the message before performing the digital signature.

The implementation language must be Java. Your program should take an additional filename in the command line and output to standard output the result of digitally signing this file. The input binary file will be the Java class file resulting from compiling your program.

You can make use of the BigInteger class (java.math.BigInteger), the security libraries (java.security.*) and the crypto libraries (javax.crypto.*). You must not make use of the multiplicative inverse or GCD methods provided by the BigInteger class; you will need to implement these yourself. You can however make use of the crypto libraries to perform the SHA-256 hashing.

Once your implementation is complete, you should create a zip file called Assignment2.zip that contains the following files:

Modulus.txt - your 1024-bit modulus n in hexadecimal (256 hex digits with no white space).
Assignment2.java - your program code file.
Assignment2.class - the result of compiling the above code file, which was digitally signed.
Signature.txt - the digital signature of the above class file produced using: "java Assignment2 Assignment2.class > Signature.txt" (in hexadecimal with no white space).
A declaration that this is solely your own work (except elements that are explicitly attributed to another source).
This assignment is due 10am on Monday 14th December. This assignment carries 15 marks and late submissions will be penalised 1.5 marks for each 24 hours the assignment is overdue.

The following are some common mistakes you should avoid on this assignment:

1. Chinese Remainder Theorem not implemented correctly.

2. Using a byte array for the code file which is too large (this will be filled up with additional zeroes and give an incorrect digest value).

3. Calculating the decryption exponent mod n rather than mod phi(n).

4. Converting BigInteger values to an array of bytes incorrectly - note that the BigInteger method toByteArray() uses a twos complement representation and may add an extra leading zero-valued byte if the first bit is set. 

5. Hashing is performed on character values in string representation of input file rather than the actual byte values.

6. Giving decimal values rather than hexadecimal.

7. Giving negative hex values.

