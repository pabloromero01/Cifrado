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

public class Cliente {

    // ✅ Debe ser EXACTAMENTE igual que en Servido
    private static final byte[] SHARED_KEY = "ClaveSuperSecre1".getBytes(StandardCharsets.UTF_8);

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {
        // ✅ PON AQUÍ LA IP DEL ORDENADOR SERVIDO
        // Ejemplo: "192.168.1.50"
        String ipServidor = "172.22.144.1";
        int puerto = 12345;

        try (Socket socket = new Socket(ipServidor, puerto)) {
            System.out.println("Conectado al servidor: " + ipServidor + ":" + puerto);

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // 1) Mensaje en claro (solo para ti)
            String mensajePlano = "Hola servidor. Soy el cliente (mensaje secreto).";

            // 2) Cifrar y enviar (Base64)
            String mensajeCifrado = encryptToBase64(mensajePlano);
            out.println(mensajeCifrado);

            System.out.println("Mensaje ENVIADO cifrado (Base64): " + mensajeCifrado);

            // 3) Recibir respuesta cifrada (Base64)
            String respuestaCifrada = in.readLine();
            System.out.println("Respuesta RECIBIDA cifrada (Base64): " + respuestaCifrada);

            // 4) Descifrar respuesta
            String respuestaPlano = decryptFromBase64(respuestaCifrada);
            System.out.println("Respuesta DESCIFRADA del servidor: " + respuestaPlano);

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
