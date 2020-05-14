import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.Arrays;

public class Server {

    final static int PORT=1200;

    public static void main(String[] args) {


        try{

            System.out.println("\nInitialization...");
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started on port " + PORT);
            System.out.println("Waiting for a client connection...");
            Socket socket = serverSocket.accept();
            System.out.println("Client online");

            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);


            /* RSA Session -- SENDING RSA PK and RSA Mod from server to client **/
            System.out.println("------------------------------------------------------------------------------------" +
                    "-----------------------------------------------------------------------------------------------");
            Utility utility = new Utility();
            utility.generateRSA();
            System.out.println("\nStarting RSA session with client : "); // Sending RSA (Public Key, Modulus) to client
            printWriter.println(utility.getRsaPublicKey());
            printWriter.println(utility.getRsaModulus());
            System.out.println("RSA (PublicKey, Modulus) transmitted, attempting to receive a message from client...");


            /* RC4 session ***/

            // Receiving RC4 Encrypted key and its posix
            BigInteger rc4EncrKey = new BigInteger(bufferedReader.readLine());
            utility.setMessageBigInt(rc4EncrKey);
            String posixStr = bufferedReader.readLine();
            String[] items = posixStr.substring(1, posixStr.length() - 1).split(",");
            int[] arr = new int[items.length];
            for (int i = 0; i < items.length; ++i)
            {
                arr[i] = Integer.parseInt(items[i].trim());
            }

            utility.setMessagePosix(arr);

            // Decoding RC4 Key
            System.out.println("\nRC4 KEY encrypted received : " + rc4EncrKey);
            byte[] rc4Key = utility.rsaDecryptByte(rc4EncrKey);
            utility.generateRC4(rc4Key);
            System.out.println("RC4 KEY decrypted : " + Arrays.toString(rc4Key));
            System.out.println("\nRC4 key received and generating RC4 session on server side done.");
            System.out.println("Starting RC4 session. ");
            System.out.println("Waiting for the RSA-RC4-Encrypted message from client...");


            // Receiving the RSA-RC4 message byte per byte in two steps
            String rec = bufferedReader.readLine();
            int k = Integer.parseInt(rec); byte b; byte[] bytes = new byte[k]; // first step is received number of bytes

            for (int i = 0; i < k; i++){ // second step is receiving byte per byte
                rec = bufferedReader.readLine();
                b = Byte.parseByte(rec);
                bytes[i] = b;
            }

            String posixStr2 = bufferedReader.readLine(); // Receiving the posix for the double encrypted message
            String[] items2 = posixStr2.substring(1, posixStr2.length() - 1).split(",");
            int[] arr2 = new int[items2.length];
            for (int i = 0; i < items2.length; ++i)
            {
                arr2[i] = Integer.parseInt(items2[i].trim()); // .trim() because it adds the space and parseInt don't like spaces
            }
            utility.setMessagePosix(arr2);


            // 4 - RC4 decrypt the byte[] and convert it to a string
            System.out.println("RSA-RC4 ENCRYPTED received.");
            System.out.println("\n Message received : ");
            System.out.println(utility.convertByteArray(bytes));
            System.out.println();
            byte[] decryptedRC4 = utility.rc4Decrypt(bytes);
            String decrypted = utility.convertByteArray(decryptedRC4);
            BigInteger bigInteger = new BigInteger(decrypted);
            System.out.println(" 4 - RC4 Decrypted : " + bigInteger);

            // 5 - BigInteger = rsaDecrypt (BigInt)
            BigInteger bigInteger1 = utility.rsaDecrypt(bigInteger);
            System.out.println(" 5 - RSA Decrypted = " + bigInteger1);

            // 6 - Decoder String = decode(BigInt, posix)
            String result = utility.decode(bigInteger1,utility.getMessagePosix());
            System.out.println(" 6 - DECODED = " + result);

            LocalDateTime now = LocalDateTime.now();
            String response = now.toString() + " received the message --> " + result;
            printWriter.println(response);

            socket.close();
            System.out.println("\nServer execution terminated.");

        }catch(Exception e){
            e.printStackTrace();
        }
    }
}