import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

/* The algorithm, summarized:
 
1, Bob picks secret primes p, q and computes n = p*q.
2, Bob picks e with gcd(e, (p-1)(q-1)) = 1.          -> public key (n, e)
3, Bob computes d with d*e = 1 (mod (p-1)(q-1)).      -> private key (n, d)
4, Alice encrypts her message m as c = m^e (mod n) and sends c to Bob.
5, Bob decrypts by computing m = c^d (mod n).
*/

public class Main {

    public static void main(String[] args) throws Exception {

        // 1. KEY GENERATION
        SecureRandom random = new SecureRandom();

        // Generate two large prime numbers p and q.
        // 512 bits each gives us a modulus n of approximately 1024 bits.
        BigInteger p = BigInteger.probablePrime(512, random);
        BigInteger q = BigInteger.probablePrime(512, random);

        // n = p * q
        BigInteger n = p.multiply(q);

        // phi(n) = (p - 1)(q - 1)
        BigInteger phi = p.subtract(BigInteger.ONE)
                          .multiply(q.subtract(BigInteger.ONE));

        // Choose the public encryption exponent e.
        // 65537 is a commonly used value for e.
        BigInteger e = BigInteger.valueOf(9007);

        // e must be relatively prime to phi(n).
        // If gcd(e, phi) != 1, generate new primes.
        while (!e.gcd(phi).equals(BigInteger.ONE)) {

            p = BigInteger.probablePrime(512, random);
            q = BigInteger.probablePrime(512, random);

            n = p.multiply(q);

            phi = p.subtract(BigInteger.ONE)
                   .multiply(q.subtract(BigInteger.ONE));
        }

        // Calculate the private exponent d.
        // d is the modular inverse of e modulo phi(n).

        // d * e ≡ 1 (mod phi(n))
        BigInteger d = e.modInverse(phi);

              // (n,e) = public key, (n,d) = private key 
              //  p, q, phi(n), d = secret        n, e = public

        // 2. DISPLAY THE KEYS
        System.out.println("RSA KEY GENERATION:");

        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("n = " + n);
        System.out.println("phi(n) = " + phi);
        System.out.println("e = " + e);
        System.out.println("d = " + d);

        System.out.println();

        System.out.println("Public key: (n, e)");
        System.out.println("Private key: (n, d)");


        // 3. READ A MESSAGE FROM THE USER
        BufferedReader reader =  new BufferedReader(new InputStreamReader(System.in));

        System.out.println();
        System.out.print("Enter a message to encrypt: ");

        String input = reader.readLine();



        // 4. CONVERT THE MESSAGE INTO A BIGINTEGER

        // Convert the String into bytes and then into a BigInteger.
        //
        // The "1" tells BigInteger that the number should be
        // interpreted as positive.
        BigInteger message = new BigInteger(
                1,
                input.getBytes(StandardCharsets.UTF_8)
        );

        // RSA requires the message number to be smaller than n.
        if (message.compareTo(n) >= 0) {
            System.out.println("Error: The message is too large.");
            System.out.println("Please enter a shorter message.");
            return;
        }


   
        // 5. ENCRYPTION
        // RSA encryption:
        //
        // c = m^e mod n
        //
        // BigInteger.modPow() performs this efficiently.
        BigInteger ciphertext = message.modPow(e, n);

        System.out.println();
        System.out.println("ENCRYPTION:");
        System.out.println("Original message: " + input);
        System.out.println("Message as number: " + message);
        System.out.println("Ciphertext: " + ciphertext);


        // 6. DECRYPTION

        // RSA decryption:
        //
        // m = c^d mod n
        //
        // Again, modPow() performs modular exponentiation efficiently.
        BigInteger decryptedMessage = ciphertext.modPow(d, n);


        // 7. CONVERT  DECRYPTED BIGINTEGER BACK INTO A STRING
        String decryptedText = new String(
                decryptedMessage.toByteArray(),
                StandardCharsets.UTF_8
        );

        System.out.println();
        System.out.println("DECRYPTION:");
        System.out.println("Decrypted number: " + decryptedMessage);
        System.out.println("Decrypted message: " + decryptedText);


        // 8. CHECK ENCRYPTION/DECRYPTION WORKED
        System.out.println();

        if (input.equals(decryptedText)) {
            System.out.println("SUCCESS: The decrypted message matches the original!");
        } else {
            System.out.println("ERROR: The messages do not match.");
        }
    }
}
