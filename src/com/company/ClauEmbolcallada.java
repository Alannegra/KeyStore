package com.company;

import com.company.utils.Xifrar;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class ClauEmbolcallada {
    public static void main(String[] args) {
        KeyPair kp = Xifrar.randomGenerate(1024);
        String textoEncriptado = "Texto a encriptar";
        byte[] bytes = textoEncriptado.getBytes(StandardCharsets.UTF_8);
        byte[][] encriptado = Xifrar.encryptWrappedData(bytes,kp.getPublic());
        byte[] desencriptado = Xifrar.decryptWrappedData(encriptado[0], kp.getPrivate(),encriptado[1]);

        String msg = new String(desencriptado);
        System.out.println(msg);
    }
}
