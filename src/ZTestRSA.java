import java.math.BigInteger;
import java.util.Scanner;

public class ZTestRSA {

    public static void main(String[] args) {

        Utility utility = new Utility();
        utility.generateRSA();
        System.out.println("\n Automatically generated an RSA instance with a 1024 key length");
        System.out.println("RSA Public Key = " + utility.getRsaPublicKey());
        System.out.println("RSA Modulus (p*q = N) = " + utility.getRsaModulus());

        System.out.println("\n Please type a message to encode : ");
        String str; Scanner scanner = new Scanner(System.in);
        str = scanner.nextLine();

        BigInteger bigInteger, bigInteger1;
        System.out.println("Message : " + str);

        bigInteger = utility.rsaEncrypt(str);
        System.out.println("RSA Encrypting : " + bigInteger);

        bigInteger1 = utility.rsaDecrypt(bigInteger);
        System.out.println("RSA Decrypting : " + bigInteger1);

        System.out.println("Decrypting the ASCII code in the BigInt : " + utility.decode(bigInteger1,utility.getMessagePosix()));

    }
}
