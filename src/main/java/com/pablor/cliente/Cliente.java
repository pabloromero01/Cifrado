package com.pablor.cliente;

// Clases necesarias para cifrado AES/GCM

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Clases para red, entrada/salida y utilidades
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Cliente {

    // Clave compartida entre cliente y servidor (16 bytes para AES-128)
    private static final byte[] SHARED_KEY = "ClaveSuperSecre1".trim().getBytes(StandardCharsets.UTF_8);

    // Longitud del IV para AES-GCM (12 bytes recomendado)
    private static final int IV_LENGTH = 12;

    // Longitud del tag de autenticación (128 bits)
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {

        // Dirección IP y puerto del servidor
        String ipServidor = "10.13.0.186";
        int puerto = 12345;

        // Se crea el socket y se conecta al servidor
        try (Socket socket = new Socket(ipServidor, puerto)) {

            System.out.println("Conectado al servidor: " + ipServidor + ":" + puerto);
            System.out.println("KEY bytes (debe ser 16): " + SHARED_KEY.length);

            // Flujo de entrada desde el servidor
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Flujo de salida hacia el servidor
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Scanner para leer desde consola
            Scanner sc = new Scanner(System.in);

            // Bucle principal de comunicación
            while (true) {

                // Leer mensaje del usuario
                System.out.print("Escribe mensaje (o 'salir'): ");
                String mensajePlano = sc.nextLine();

                // Cifrar el mensaje y enviarlo al servidor
                String mensajeCifrado = encryptToBase64(mensajePlano);
                out.println(mensajeCifrado);

                // Leer la respuesta cifrada del servidor
                String respuestaCifrada = in.readLine();
                if (respuestaCifrada == null) {
                    System.out.println("El servidor cerró la conexión.");
                    break;
                }

                // Descifrar la respuesta
                String respuestaPlano = decryptFromBase64(respuestaCifrada);
                System.out.println("Respuesta DESCIFRADA del servidor: " + respuestaPlano);

                // Si el usuario escribe "salir", termina el programa
                if (mensajePlano.equalsIgnoreCase("salir")) {
                    break;
                }
            }

        } catch (Exception e) {
            // Muestra cualquier error que ocurra
            e.printStackTrace();
        }
    }

    // Devuelve la clave secreta AES a partir del array de bytes
    private static SecretKey getKey() {
        return new SecretKeySpec(SHARED_KEY, "AES");
    }

    // Cifra un texto plano y lo devuelve en Base64
    private static String encryptToBase64(String plaintext) throws Exception {

        // Generar IV aleatorio
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Crear el cifrador AES en modo GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(), spec);

        // Cifrar el texto
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Unir IV + texto cifrado
        byte[] packed = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, packed, 0, iv.length);
        System.arraycopy(ciphertext, 0, packed, iv.length, ciphertext.length);

        // Codificar en Base64 para enviar como texto
        return Base64.getEncoder().encodeToString(packed);
    }

    // Descifra un mensaje recibido en Base64
    private static String decryptFromBase64(String base64Payload) throws Exception {

        // Decodificar Base64
        byte[] packed = Base64.getDecoder().decode(base64Payload);

        // Comprobar tamaño mínimo
        if (packed.length < IV_LENGTH + 1) {
            throw new IllegalArgumentException("Payload demasiado corto.");
        }

        // Separar IV y texto cifrado
        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[packed.length - IV_LENGTH];

        System.arraycopy(packed, 0, iv, 0, IV_LENGTH);
        System.arraycopy(packed, IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Crear el cifrador para descifrar
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, getKey(), spec);

        // Descifrar y devolver el texto plano
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}