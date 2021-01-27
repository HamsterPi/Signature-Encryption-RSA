/*
    2020/2021 CA4005 Cryptography and Security Protocols
    Assignment 2: Digital Signature Using RSA
    By Connell Kelly

    Resources:
        - www.tutorialspoint.com/java/math/biginteger_probableprime (Probable prime generation instructions)
        - https://asecuritysite.com/ (Probable prime generator and RSA information)
        - https://stackoverflow.com/ (Instructions and reference points for evaluating various project steps)
*/

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static java.util.Collections.singletonList;
import java.util.List;
import java.util.Scanner;

public class Assignment2 {

    // Methods above 'main()' are organised alphabetically.

    private static BigInteger crtDecrypt(BigInteger a, BigInteger b, BigInteger p, BigInteger q)
    {
        // Simplify Chinese Remainder Theorem components..
        BigInteger apPrime = modExpo(a, b.mod(p.subtract(new BigInteger("1"))), p);
        BigInteger aqPrime = modExpo(a, b.mod(q.subtract(new BigInteger("1"))), q);

        // Determine multiplicative inverse for probable primes.
        BigInteger qmpInverse = multInverse(q, p);

        // Return CRT.
        return aqPrime.add(q.multiply((qmpInverse.multiply(apPrime.subtract(aqPrime))).mod(p)));
    }

    private static BigInteger[] evalGCD(BigInteger a, BigInteger b)
    {
        // Determine the greatest common denominator of two inputs.
        if (b.equals(new BigInteger("0")))
            return new BigInteger[]{new BigInteger("1"), new BigInteger("0"), a};

        // Evaluate GCD for 'a.mod(b)'.
        BigInteger[] abGCD = evalGCD(b, a.mod(b));
        return new BigInteger[] {abGCD[1], abGCD[0].subtract((a.divide(b)).multiply(abGCD[1])), abGCD[2]};
    }

    private static BigInteger modExpo(BigInteger a, BigInteger expo, BigInteger mod)
    {
        // Determine bitlength 'bitLen'.
        int bitLen = expo.bitLength();
        BigInteger b = new BigInteger("1");

        // Square and multiply inputs (Based on my DHKA method).
        for (int i = bitLen - 1; i >= 0; i--)
        {
            b = b.multiply(b).mod(mod);
            if (expo.testBit(i))
            {
                b = b.multiply(a).mod(mod);
            }
        }
        return b;
    }

    private static BigInteger multInverse(BigInteger a, BigInteger b)
    {
        // Determine multiplicative inverse of two inputs.
        BigInteger[] abMultInverse = evalGCD(a, b);
        return abMultInverse[0];
    }

    private static void writeValue(String path, String strOutput) throws IOException
    {
        // Write modulus 'n' to an indicated file.
        Charset utf8 = StandardCharsets.UTF_8;
        List<String> outputList = singletonList(strOutput);
        Files.write(Paths.get(path), outputList, utf8);
    }

    public static void main(String[] args) throws FileNotFoundException
    {
        // RSA Digital Signature components.
        // Encryption exponent 'e'.
        BigInteger e = new BigInteger("65537");
        // Probable prime 'p'.
        BigInteger p;
        // Probable prime 'q'.
        BigInteger q;
        // Product of 'p' and 'q'.
        BigInteger n;
        // Euler totient of 'n'.
        BigInteger eulerT;
        // List for GCD of 'e' and 'eulerT'.
        BigInteger[] eeGCD;
        // Identify file containing a pair of probable primes.
        // Predetermined probable primes alleviates randomness.
        File fileText = new File("primes.txt");

        do
        {
            // Obtain probable primes.
            Scanner s = new Scanner(fileText);
            p = s.nextBigInteger();
            q = s.nextBigInteger();

            // Evaluate product of primes 'p' and 'q' for 'n'.
            n = p.multiply(q);

            // Determine Euler totient 'eulerT'.
            eulerT = p.subtract(new BigInteger("1")).multiply(q.subtract(new BigInteger("1")));

            // Evaluate GCD for 'e' and 'eulerT'.
            eeGCD = evalGCD(e, eulerT);
          // Determines if 'e' and 'eulerT' are relatively prime.
        } while (!(eeGCD[2].equals(new BigInteger("1"))));

        // Decryption exponent 'decExp'.
        BigInteger decExp = eeGCD[0];

        try
        {
            // Using the inputted file, determine digest 'dig' with the function SHA-256.
            MessageDigest messageDig = MessageDigest.getInstance("SHA-256");
            BigInteger dig = new BigInteger(1, messageDig.digest(Files.readAllBytes(Paths.get(args[0]))));

            // Using the private key, sign digest 'dig' with 'crtDecrypt'.
            BigInteger signDig = crtDecrypt(dig, decExp, p, q);

            // Convert 1024-bit modulus n to hexidecimal format and write to modulo-n.txt.
            writeValue("Modulus", n.toString(16));

            // Convert signed digest to hexidecimal format and write to signed-digest.txt.
            System.out.print(signDig.toString(16));

        } catch
        (IOException
                        | NoSuchAlgorithmException ex)
        {
            ex.printStackTrace();
        }
    }
}
