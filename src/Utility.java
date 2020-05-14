import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/***
 * The RSA algorithm credits goes to https://introcs.cs.princeton.edu/java/99crypto/RSA.java.html
 * The RC4 algorithm credits goes to https://gist.github.com/songzhiyong/8451195
 *
 * Therefore, I rewrote a lot of parts of both of these codes in order to adapt it to this type of task
 */

class Utility {


    private final static BigInteger one      = new BigInteger("1");
    private final static SecureRandom random = new SecureRandom();

    private BigInteger rsaPublicKey = new BigInteger("65537"); // Common value
    private BigInteger rsaPrivateKey;
    private BigInteger rsaModulus; // N = p * q


    private int[] messagePosix;
    private BigInteger messageBigInt;

    //RC4 variables
    private final byte[] S = new byte[256];
    private final byte[] T = new byte[256];
    byte[] defaultKey = new byte[]{(byte) 63, (byte) 72, (byte) 79, (byte) 70, (byte) 74, (byte) 69, (byte) 69};

    void generateRSA(int N){

        BigInteger p = BigInteger.probablePrime(N/2, random);
        BigInteger q = BigInteger.probablePrime(N/2, random);
        BigInteger phi = (p.subtract(one)).multiply(q.subtract(one));

        rsaModulus = p.multiply(q);
        rsaPrivateKey = rsaPublicKey.modInverse(phi);

    }

    void generateRSA(){ generateRSA(1024);}

    private BigInteger rsaEncrypt(BigInteger message){
        return message.modPow(rsaPublicKey, rsaModulus);
    }

    BigInteger rsaEncrypt(String message) {
        return rsaEncrypt(messageToAscii(message));
    }

    BigInteger rsaDecrypt(BigInteger encrypted) {
        return encrypted.modPow(rsaPrivateKey, rsaModulus);
    }

    BigInteger rsaEncryptByte(byte[] bytes){

        StringBuilder stringBuilder = new StringBuilder();
        for (byte b: bytes) { stringBuilder.append(b).append(','); }
        String str = stringBuilder.toString().substring(0,stringBuilder.toString().length()-1);
        return rsaEncrypt(str);
    }

    byte[] rsaDecryptByte(BigInteger encrypted) {

        BigInteger bigInteger = rsaDecrypt(encrypted);
        int index = 0; String sub; int nb; char[] chars = new char[messagePosix.length]; char ch;
        String s = bigInteger.toString();
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < chars.length; i++){
            sub = s.substring(index, index + messagePosix[i]);
            nb = Integer.parseInt(sub);
            ch = (char) nb;
            chars[i] = ch;
            stringBuilder.append(ch);
            index += messagePosix[i];
        }

        String init = stringBuilder.toString();
        String[] values = init.split(",");
        byte[] result = new byte[values.length];
        for (int i = 0; i < result.length; i++){

            result[i] = Byte.valueOf(values[i]);
        }
        return result;
    }

    BigInteger getRsaPublicKey() {
        return rsaPublicKey;
    }

    void setRsaPublicKey(BigInteger rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    BigInteger getRsaModulus() {
        return rsaModulus;
    }

    void setRsaModulus(BigInteger rsaModulus) {
        this.rsaModulus = rsaModulus;
    }

    private BigInteger messageToAscii(String str){

        this.messagePosix = new int[str.length()];
        int num;
        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < str.length(); i++){
            num = (int) str.charAt(i);
            messagePosix[i] = (int)(Math.log10(num)+1);
            stringBuilder.append(num);
        }

        this.messageBigInt = new BigInteger(stringBuilder.toString());
        return messageBigInt;
    }

    String decode(BigInteger message, int[] posix){

        int index = 0; String sub; int nb; char[] chars = new char[posix.length]; char ch;
        String s = message.toString(); StringBuilder stringBuilder = new StringBuilder();


        for (int i = 0; i < chars.length; i++){
            sub = s.substring(index, index + posix[i]);
            nb = Integer.parseInt(sub);
            ch = (char) nb;
            chars[i] = ch;
            stringBuilder.append(ch);
            index += posix[i];
        }

        return stringBuilder.toString();

    }

    int[] getMessagePosix() {
        return messagePosix;
    }

    void setMessagePosix(int[] messagePosix) {
        this.messagePosix = messagePosix;
    }

    void setMessageBigInt(BigInteger messageBigInt) {
        this.messageBigInt = messageBigInt;
    }

    void generateRC4(final byte[] key) {
        if (key.length < 1 || key.length > 256) {
            throw new IllegalArgumentException(
                    "key must be between 1 and 256 bytes");
        } else {
            int keylen = key.length;
            for (int i = 0; i < 256; i++) {
                S[i] = (byte) i;
                T[i] = key[i % keylen];
            }
            int j = 0;
            for (int i = 0; i < 256; i++) {
                j = (j + S[i] + T[i]) & 0xFF;
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
        }
    }

    void generateRC4(){ generateRC4(defaultKey);}

    private byte[] rc4Encrypt(final byte[] plaintext) {
        final byte[] ciphertext = new byte[plaintext.length];
        int i = 0, j = 0, k, t;
        byte[] copyS = Arrays.copyOf(S,S.length);

        for (int counter = 0; counter < plaintext.length; counter++) {
            i = (i + 1) & 0xFF;
            j = (j + copyS[i]) & 0xFF;
            byte temp = copyS[i];
            copyS[i] = copyS[j];
            copyS[j] = temp;
            t = (copyS[i] + copyS[j]) & 0xFF;
            k = copyS[t];
            ciphertext[counter] = (byte) (plaintext[counter] ^ k);

        }
        return ciphertext;
    }

    byte[] rc4Encrypt(String string){ return rc4Encrypt(string.getBytes()); }

    byte[] rc4Decrypt(final byte[] ciphertext) {
        return rc4Encrypt(ciphertext);
    }

    String convertByteArray(byte[] bytes){

        StringBuilder stringBuilder = new StringBuilder();
        for (byte b: bytes) { stringBuilder.append((char) b); }
        return stringBuilder.toString();
    }

}
