package com.pablor.servidor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class Servidor {

    // 16 bytes exactos (AES-128)
    private static final byte[] SHARED_KEY =
            "ClaveSuperSecre16".getBytes(StandardCharsets.UTF_8);

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {
        int puerto = 12345;

        try (ServerSocket serverSocket = new ServerSocket(puerto)) {
            System.out.println("Servidor escuchando en el puerto " + puerto + "...");

            try (Socket clientSocket = serverSocket.accept()) {
                System.out.println("Cliente conectado desde: " + clientSocket.getInetAddress());

                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                while (true) {
                    // 1) Recibir mensaje cifrado (Base64)
                    String payloadBase64 = in.readLine();
                    if (payloadBase64 == null) {
                        System.out.println("El cliente ha cerrado la conexión.");
                        break;
                    }

                    // 2) Descifrar
                    String mensajePlano;
                    try {
                        mensajePlano = decryptFromBase64(payloadBase64);
                    } catch (Exception e) {
                        System.out.println("Error descifrando. Payload recibido: " + payloadBase64);
                        e.printStackTrace();
                        break;
                    }

                    System.out.println("Cliente dice: " + mensajePlano);

                    // Salida limpia
                    if (mensajePlano.equalsIgnoreCase("salir")) {
                        String bye = encryptToBase64("Servidor: conexión cerrada.");
                        out.println(bye);
                        System.out.println("Cerrando por 'salir'.");
                        break;
                    }

                    // 3) Responder cifrado
                    String respuesta = "Servidor: recibido -> [" + mensajePlano + "]";
                    String respuestaCifrada = encryptToBase64(respuesta);

                    out.println(respuestaCifrada);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey getKey() {
        return new SecretKeySpec(SHARED_KEY, "AES");
    }

    private static String encryptToBase64(String plaintext) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(), spec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] packed = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, packed, 0, iv.length);
        System.arraycopy(ciphertext, 0, packed, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(packed);
    }

    private static String decryptFromBase64(String base64Payload) throws Exception {
        byte[] packed = Base64.getDecoder().decode(base64Payload);

        if (packed.length < IV_LENGTH + 1) {
            throw new IllegalArgumentException("Payload demasiado corto.");
        }

        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[packed.length - IV_LENGTH];

        System.arraycopy(packed, 0, iv, 0, IV_LENGTH);
        System.arraycopy(packed, IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, getKey(), spec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}

