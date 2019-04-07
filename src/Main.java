import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {

    public static void main(String[] args) {


        List<String> arguments = new ArrayList<String>(Arrays.asList(args));
        String inputFile,outputFile,keysFile;
        inputFile = outputFile = keysFile = "";
        if (arguments.indexOf("-e") != -1){
            try {
                inputFile = arguments.get(arguments.indexOf("-i") + 1);
                outputFile = arguments.get(arguments.indexOf("-o") + 1);
                keysFile = arguments.get(arguments.indexOf("-k") + 1);

                Byte [] message = ReadFile(inputFile);
                Byte [] keys = ReadFile(keysFile);
                WriteFile(outputFile,AES3Encrypt(keys,message));
            } catch (IOException e) {

            }
        }
        else if (arguments.indexOf("-d") != -1){
            try {
                inputFile = arguments.get(arguments.indexOf("-i") + 1);
                outputFile = arguments.get(arguments.indexOf("-o") + 1);
                keysFile = arguments.get(arguments.indexOf("-k") + 1);

                Byte [] message = ReadFile(inputFile);
                Byte [] keys = ReadFile(keysFile);
                WriteFile(outputFile,AES3Decrypt(keys,message));
            } catch (IOException e) {

            }
        }
        else if (arguments.indexOf("-b") != -1){
            try {
                String inputMessageFile = arguments.get(arguments.indexOf("-m") + 1);
                String inputCipherFile = arguments.get(arguments.indexOf("-c") + 1);
                outputFile = arguments.get(arguments.indexOf("-o") + 1);

                Byte[] message = ReadFile(inputMessageFile);
                Byte[] enc_message = ReadFile(inputCipherFile);
                Byte [] keys = cipher(Arrays.copyOfRange(message,0,16),Arrays.copyOfRange(enc_message,0,16));
                WriteFile(outputFile, keys);
            }catch (IOException e){
            }
        }
        else {
            System.out.println(
                    "\t–e : instruction to encrypt the input file \n" +
                            "\t–d: instruction to decrypt the input file \n" +
                            "\t–k <path>: path to the keys, the key should be 384 bit (128*3) for 〖AES〗_3^*. and should be divided into 3 separate keys. \n" +
                            "\t–i <input file path>: a path to a file we want to encrypt/decrypt \n" +
                            "\t–o <output file path>: a path to the output file \n" +
                            "\t Usage: Java –jar aes.jar -e/-d –k <path-to-key-file > -i <path-to-input-file> -o <path-to-output-file> \n\n" +
                            "\t–b : instruction to break the encryption algorithm \n" +
                            "\t–m <path>: denotes the path to the plain-text message \n" +
                            "\t–c <path>: denotes the path to the cipher-text message \n" +
                            "\t–o <path>: a path to the output file with the key(s) found. \n" +
                            "\tUsage: Java –jar aes.jar -b –m <path-to-message> –c <path-to-cipher> -o < output-path> \n"
            );
        }
    }

    public static void WriteFile(String fileName,Byte [] data) throws IOException {
        FileOutputStream outputStream = new FileOutputStream(fileName);
        byte [] out = new byte[data.length];
        for (int i = 0; i < data.length; i++)
            out[i] = data[i].byteValue();
        outputStream.write(out);
        outputStream.close();
    }

    public static Byte[] ReadFile(String fileName) throws IOException {
        byte [] tmp = Files.readAllBytes(Paths.get(fileName));
        Byte [] ans = new Byte[tmp.length];
        for (int i = 0; i < ans.length; i++) {
            ans[i] = tmp[i];
        }
        return ans;
    }

    //region Encryption
    public static Byte [] AES3Encrypt(Byte [] key, Byte [] message){

        for (int i = 0; i < key.length / 16 ; i++) {
            Byte [] key16 = Arrays.copyOfRange(key,i*16,(i*16)+16);
            List<Byte> enc_message = new ArrayList<Byte>();
            for (int j = 0; j < message.length / 16; j++) {
                Byte [] message16 = Arrays.copyOfRange(message,j*16,(j*16)+16);
                enc_message.addAll(Arrays.asList(AESEncrypt(key16,message16)));
            }
            for (int j = 0; j < message.length; j++) {
                message[j] = enc_message.get(j);
            }
        }

        return message;
    }

    public static Byte [] AESEncrypt(Byte [] key, Byte [] message){
        Byte [] enc_message = new Byte[message.length];

        enc_message = ShiftRowsLeft(message);
        enc_message = xor(key,enc_message);
        
        return enc_message;
    }

    public static Byte [] ShiftRowsLeft(Byte [] message){

        Byte [] sft_message = new Byte[message.length];
        for (int i = 0; i < message.length; i++) {
            sft_message[(16 - (4 * (i%4)) + i) % 16] = message[i];
        }

        return sft_message;
    }


    //endregion

    //region Decryption
    public static Byte [] AES3Decrypt(Byte [] key,Byte [] message){

        for (int i = (key.length / 16) - 1; i >= 0  ; i--) {
            Byte [] key16 = Arrays.copyOfRange(key,i*16,(i*16)+16);
            List<Byte> dec_message = new ArrayList<Byte>();
            for (int j = 0; j < message.length / 16; j++) {
                Byte [] message16 = Arrays.copyOfRange(message,j*16,(j*16)+16);
                dec_message.addAll(Arrays.asList(AESDecrypt(key16,message16)));
            }
            for (int j = 0; j < message.length; j++) {
                message[j] = dec_message.get(j);
            }
        }

        return message;
    }

    public static Byte [] AESDecrypt(Byte [] key, Byte [] message){
        Byte [] dec_message = new Byte[message.length];

        dec_message = xor(key,message);
        dec_message = ShiftRowsRight(dec_message);

        return dec_message;
    }

    public static Byte [] ShiftRowsRight(Byte [] message){

        Byte [] sft_message = new Byte[message.length];
        for (int i = 0; i < message.length; i++) {
            sft_message[((4 * (i % 4)) + i) % 16] = message[i];
        }

        return sft_message;
    }
    //endregion

    //region Cipher
    public static Byte [] cipher(Byte [] message,Byte [] enc_message){

        Byte [] key = new Byte [48];
        for (int i = 0; i < message.length; i++) {
            int index1 = (16 - (4 * (i%4)) + i) % 16;
            int index2 = (16 - (4 * (index1%4)) + index1) % 16;
            int index3 = (16 - (4 * (index2%4)) + index2) % 16;
            Byte [] keys = split_keys(message[i],enc_message[index3]);
            key[index3 + 32] = keys[2];
            key[index2 + 16] = keys[1];
            key[index1] = keys[0];
        }
        return key;
    }


    public static Byte[] split_keys(Byte m,Byte c){
        String ms = String.format("%8s",Integer.toBinaryString(m & 0xFF)).replace(' ','0');
        String cs = String.format("%8s",Integer.toBinaryString(c & 0xFF)).replace(' ','0');
        String k1,k2,k3 ;
        k1 = k2 = k3 = "";
        for (int i = 0; i < ms.length(); i++) {
            if (cs.charAt(i) == '0' && ms.charAt(i) == '0'){
                k1 += "1";
                k2 += "0";
                k3 += "1";
            }
            else if (cs.charAt(i) == '1' && ms.charAt(i) == '1') {
                k1 += "0";
                k2 += "1";
                k3 += "1";
            }
            else if (cs.charAt(i) == '1' && ms.charAt(i) == '0'){
                k1 += "0";
                k2 += "0";
                k3 += "1";
            }
            else {
                k1 += "1";
                k2 += "0";
                k3 += "0";
            }
        }
        return new Byte [] {(byte)Integer.parseInt(k1,2),(byte)Integer.parseInt(k2,2),(byte)Integer.parseInt(k3,2)};
    }
    //endregion


    public static Byte[] xor(Byte[] key, Byte[] message) {
        Byte [] xor_message = new Byte[message.length];
        for (int i = 0; i < key.length; i++) {
            xor_message[i] = (byte)(message[i] ^ key[i]);
        }
        return xor_message;
    }
}
