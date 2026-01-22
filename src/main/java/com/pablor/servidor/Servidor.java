package com.pablor.servidor;

// Clases necesarias para cifrado AES/GCM

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Clases para red, entrada/salida y utilidades
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class Servidor {

    // Clave compartida entre cliente y servidor (16 bytes para AES-128)
    private static final byte[] SHARED_KEY = "ClaveSuperSecre1".trim().getBytes(StandardCharsets.UTF_8);

    // Longitud del IV para AES-GCM (12 bytes recomendado)
    private static final int IV_LENGTH = 12;

    // Longitud del tag de autenticación (128 bits)
    private static final int TAG_LENGTH_BIT = 128;

    public static void main(String[] args) {

        // Puerto en el que el servidor va a escuchar
        int puerto = 12345;

        // Crear el servidor y empezar a escuchar conexiones
        try (ServerSocket serverSocket = new ServerSocket(puerto)) {

            System.out.println("Servidor escuchando en el puerto " + puerto + "...");
            System.out.println("KEY bytes (debe ser 16): " + SHARED_KEY.length);

            // Esperar a que un cliente se conecte
            try (Socket clientSocket = serverSocket.accept()) {

                System.out.println("Cliente conectado desde: " + clientSocket.getInetAddress());

                // Flujo de entrada desde el cliente
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                // Flujo de salida hacia el cliente
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

                // Bucle principal de comunicación
                while (true) {

                    // 1) Recibir mensaje cifrado en Base64
                    String payloadBase64 = in.readLine();
                    if (payloadBase64 == null) {
                        System.out.println("El cliente cerró la conexión.");
                        break;
                    }

                    // 2) Descifrar el mensaje recibido
                    String mensajePlano;
                    try {
                        mensajePlano = decryptFromBase64(payloadBase64);
                    } catch (Exception e) {
                        System.out.println("Error descifrando el mensaje.");
                        e.printStackTrace();
                        break;
                    }

                    // Mostrar el mensaje descifrado
                    System.out.println("Cliente (descifrado): " + mensajePlano);

                    // 3) Si el cliente escribe "salir", cerrar la conexión
                    if (mensajePlano.equalsIgnoreCase("salir")) {

                        String byeCifrado = encryptToBase64("Servidor: conexión cerrada.");
                        out.println(byeCifrado);

                        System.out.println("Cerrando conexión por 'salir'.");
                        break;
                    }

                    // 4) Preparar respuesta del servidor
                    String respuesta = "Servidor: recibido -> [" + mensajePlano + "]";

                    // Cifrar la respuesta
                    String respuestaCifrada = encryptToBase64(respuesta);

                    // Enviar la respuesta cifrada
                    out.println(respuestaCifrada);
                }
            }

        } catch (Exception e) {
            // Manejo de errores generales
            e.printStackTrace();
        }
    }

    // Devuelve la clave secreta AES a partir del array de bytes
    private static SecretKey getKey() {
        return new SecretKeySpec(SHARED_KEY, "AES");
    }

    // Cifra un texto plano y lo devuelve codificado en Base64
    private static String encryptToBase64(String plaintext) throws Exception {

        // Generar un IV aleatorio
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Crear el cifrador AES/GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(), spec);

        // Cifrar el texto
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Unir IV + texto cifrado
        byte[] packed = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, packed, 0, iv.length);
        System.arraycopy(ciphertext, 0, packed, iv.length, ciphertext.length);

        // Codificar el resultado en Base64
        return Base64.getEncoder().encodeToString(packed);
    }

    // Descifra un mensaje recibido en Base64
    private static String decryptFromBase64(String base64Payload) throws Exception {

        // Decodificar Base64
        byte[] packed = Base64.getDecoder().decode(base64Payload);

        // Comprobar que el tamaño sea válido
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