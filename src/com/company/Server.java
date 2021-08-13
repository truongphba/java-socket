package com.company;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Server {
    public static void main(String[] args) {

        String sentence_from_client;
        String sentence_to_client;

        try{

            PrivateKey privateKey = getPrivateKey();
            PublicKey publicKey = getPublicKey();
            ServerSocket welcomeSocket = new ServerSocket(8088);

            while(true) {
                Socket connectionSocket = welcomeSocket.accept();
                BufferedReader inFromClient =
                        new BufferedReader(new
                                InputStreamReader(connectionSocket.getInputStream()));

                DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
                sentence_from_client = inFromClient.readLine();
                System.out.println(sentence_from_client);
                sentence_to_client = connectionSocket.getRemoteSocketAddress().toString() + " said: " + sentence_from_client;

                Cipher cipherPublic = Cipher.getInstance("RSA");
                cipherPublic.init(Cipher.ENCRYPT_MODE, publicKey);
                String original = sentence_to_client;
                byte[] byteEncrypted = cipherPublic.doFinal(original.getBytes());
                String encrypted =  Base64.getEncoder().encodeToString(byteEncrypted);
                outToClient.writeBytes(encrypted);

                Cipher cipherPrivate = Cipher.getInstance("RSA");
                cipherPrivate.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] byteDecrypted = cipherPrivate.doFinal(sentence_from_client.getBytes());
                String decrypted =  Base64.getEncoder().encodeToString(byteDecrypted);
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
