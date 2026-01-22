package com.pablor.cliente;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Cliente {

    // ✅ 16 bytes EXACTOS (AES-128). Debe ser igual en Servidor
    private static final byte[] SHARED_KEY =
            "ClaveSuperSecre1".trim().getBytes(StandardCharsets.UTF_8);



    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {
        String ipServidor = "10.13.3.85";
        int puerto = 12345;

        try (Socket socket = new Socket(ipServidor, puerto)) {
            System.out.println("Conectado al servidor: " + ipServidor + ":" + puerto);
            System.out.println("KEY bytes (debe ser 16): " + SHARED_KEY.length);

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            Scanner sc = new Scanner(System.in);

            while (true) {
                System.out.print("Escribe mensaje (o 'salir'): ");
                String mensajePlano = sc.nextLine();

                // 1) Cifrar y enviar
                String mensajeCifrado = encryptToBase64(mensajePlano);
                out.println(mensajeCifrado);

                // 2) Recibir respuesta cifrada
                String respuestaCifrada = in.readLine();
                if (respuestaCifrada == null) {
                    System.out.println("El servidor cerró la conexión.");
                    break;
                }

                // 3) Descifrar y mostrar
                String respuestaPlano = decryptFromBase64(respuestaCifrada);
                System.out.println("Respuesta DESCIFRADA del servidor: " + respuestaPlano);

                // 4) Si escribimos salir, terminamos
                if (mensajePlano.equalsIgnoreCase("salir")) {
                    break;
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
