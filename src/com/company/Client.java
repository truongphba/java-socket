package com.company;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    public static void main(String[] args) {
        String sentence_to_server;
        String sentence_from_server;

        try {
            PrivateKey privateKey = getPrivateKey();
            PublicKey publicKey = getPublicKey();
            while(true) {
                System.out.print("Input from client: ");
                BufferedReader inFromUser =
                        new BufferedReader(new InputStreamReader(System.in));
                sentence_to_server = inFromUser.readLine();
                Socket clientSocket = new Socket("127.0.0.1", 8088);

                DataOutputStream outToServer =
                        new DataOutputStream(clientSocket.getOutputStream());

                BufferedReader inFromServer =
                        new BufferedReader(new
                                InputStreamReader(clientSocket.getInputStream()));

                Cipher cipherPrivate = Cipher.getInstance("RSA");
                cipherPrivate.init(Cipher.ENCRYPT_MODE, publicKey);
                String original = sentence_to_server;
                byte[] byteEncrypted = cipherPrivate.doFinal(original.getBytes());
                String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
                outToServer.writeBytes(encrypted);


                sentence_from_server = inFromServer.readLine();
                Cipher cipherPublic = Cipher.getInstance("RSA");
                cipherPublic.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] byteDecrypted = cipherPublic.doFinal(sentence_from_server.getBytes());
                String decrypted = Base64.getEncoder().encodeToString(byteDecrypted);
                System.out.println(decrypted);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static PrivateKey getPrivateKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(GenerateKeys.PRIVATE_KEY_FILE).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    public static PublicKey getPublicKey() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(GenerateKeys.PUBLIC_KEY_FILE).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
