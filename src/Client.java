import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Arrays;
import java.util.Scanner;



public class Client {

    public static void main(String[] args) {


        try{
            System.out.println("\nConnection...");
            Socket socket = new Socket("localhost",Server.PORT);
            System.out.println("Connected to server on port " + Server.PORT);

            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);

            /* RSA session --> Receiving RSA PK and RSA Mod ***/
            System.out.println("------------------------------------------------------------------------------------" +
                    "-----------------------------------------------------------------------------------------------");
            BigInteger rsapk, rsamod; //RSA primary key and modulus generated on the server
            Utility utility = new Utility();
            utility.generateRSA();
            System.out.println("\nStarting RSA session with server...");
            System.out.println("Receiving RSA (PublicKey, Modulus)...");
            rsapk = new BigInteger(bufferedReader.readLine());
            rsamod = new BigInteger(bufferedReader.readLine());
            utility.setRsaPublicKey(rsapk);
            utility.setRsaModulus(rsamod);
            System.out.println("Information received.");
            System.out.println("RSA PublicKey : " + rsapk);
            System.out.println("RSA Modulus : " + rsamod);

            /* RC4 session ***/


            System.out.println("\nGenerating RC4 KEY and attemtping sending it to server...");
            byte[] rc4Key = new byte[]{(byte) 11, (byte) 23, (byte) 67, (byte) 19, (byte) 101, (byte) 11, (byte) 3};
            utility.generateRC4(rc4Key);

            // Encrypting the RC4 key with RSA and Sending it from client to server
            BigInteger rc4EncrKey = utility.rsaEncryptByte(rc4Key);
            System.out.println("RC4 KEY generated : " + Arrays.toString(rc4Key));
            System.out.println("RC4 KEY Encrypted (RSA) : " + rc4EncrKey);
            printWriter.println(rc4EncrKey);
            printWriter.println(Arrays.toString(utility.getMessagePosix()));
            System.out.println("RC4 KEY transmitted.");
            System.out.println("Starting RC4 session with server...");

            /* RSA-RC4 SESSION ***/
            Scanner scanner = new Scanner(System.in);
            System.out.println("Please type a text to send to the server : ");
            String message = scanner.nextLine();
            System.out.println("- Attempting to send the message : " + message);

            // 1 - BigInteger = rsaEncrypt(String)
            BigInteger rsaEncr = utility.rsaEncrypt(message);
            System.out.println(" 1 - RSA Encrypted : " + rsaEncr);

            // 2 - RC4 encrypt the BigInt
            byte[] messageEncrypted = utility.rc4Encrypt(rsaEncr.toString());
            System.out.println(" 2 - RC4 Encrypted : ");
            System.out.println(utility.convertByteArray(messageEncrypted));

            // 3 - Sending the byte[] of the RSA-RC4 encrypted message and the posix int[] to decode

            printWriter.println(messageEncrypted.length); // Number of the bytes of the double encoded

            for(byte b : messageEncrypted){ printWriter.println(b); } // Sending byte per byte

            printWriter.println(Arrays.toString(utility.getMessagePosix())); // Essential for decoding

            System.out.println(" 3 - RSA-RC4 Encrypted message sent to the server.");

            message = bufferedReader.readLine();
            System.out.println("\nThe server has confirmed the reception of this message : " + message);
            System.out.println("\nClient execution ended successfully");


        }catch(Exception e){
            e.printStackTrace();
        }
    }

}
