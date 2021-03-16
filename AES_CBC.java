
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.io.*;

public class AES_CBC {
    public static int tamanhoIV;
    public static byte[] iv;
    public static IvParameterSpec ivParameterSpec;
    
    public static void main(String[] args) throws Exception {

    //  Pegando o texto digitado pelo usuário  
        System.out.println("Digite um texto para ser encriptado: ");
        Scanner in = new Scanner(System.in);
        String texto = in.nextLine();
        
        String key = genKey().toString();

    //  Chamando os metódos de encriptação e decriptação 
        byte[] encrypted = encrypt(texto, key);
        String decrypted = decrypt(encrypted, key);
        
        //Escrevendo texto encriptado em um arquivo:
        try (FileOutputStream fos = new FileOutputStream("textoEncriptado.txt")) { fos.write(encrypted); fos.close();}

    // 
        System.out.println("Texto encriptado:"+encrypted);
        System.out.println("Texto desencriptado:"+decrypted);

    }
    public static byte[] genKey() throws NoSuchAlgorithmException {
        // Gerando uma chave aleatória:
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        byte[] key = keygen.generateKey().getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        return key;
    }

    public static void genIV() throws IOException{
        // Gerando o IV:
        tamanhoIV = 16;
        iv = new byte[tamanhoIV];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        ivParameterSpec = new IvParameterSpec(iv);
		
        //Salvando o IV em um arquivo de texto:
        try (FileOutputStream fos = new FileOutputStream("IV.txt")) { fos.write(iv); fos.close();}         
    }
 
    public static byte[] encrypt(String plainText, String key) throws Exception {
        byte[] texto = plainText.getBytes();
		
		//Invocação do metódo que cria o IV:
        genIV();

        // Fazendo o Hashing da Chave:
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encriptação:
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(texto);

        // Combinando o IV e a parte encriptada:
        byte[] encryptedIVAndText = new byte[tamanhoIV + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, tamanhoIV);
        System.arraycopy(encrypted, 0, encryptedIVAndText, tamanhoIV, encrypted.length);

        return encryptedIVAndText;
    }

    public static String decrypt(byte[] encryptedIvTextBytes, String key) throws Exception {
        int tamanhoIV = 16;
        int keySize = 16;

        // Extraindo o IV:
        byte[] iv = new byte[tamanhoIV];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extraindo a parte encriptada:
        int encryptedSize = encryptedIvTextBytes.length - tamanhoIV;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, tamanhoIV, encryptedBytes, 0, encryptedSize);

        // Chave hash:
        byte[] keyBytes = new byte[keySize];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes());
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Desencriptação:
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }
}