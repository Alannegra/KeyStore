package com.company;

import com.company.utils.Xifrar;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

public class Ejercicio2 {
    public static void main(String[] args) throws Exception {


        // i

        String keystoreTerminal = "../../keystore_abril.ks";
        String keystoreTerminal2 = "../../keystore_abril2.ks";
        String keystorePassword = "usuario";

        KeyStore keyStore = Xifrar.loadKeyStore(keystoreTerminal2,keystorePassword);

        System.out.println(keyStore.getType());
        System.out.println(keyStore.size());

        Enumeration<String> a = keyStore.aliases();
        Collections.list(a).forEach(o -> {
            System.out.println(o);
            try {
                System.out.println(keyStore.getCertificateChain(o));
                System.out.println(keyStore.getCertificate(o));
                Certificate certificate = keyStore.getCertificate(o);
                certificate.getPublicKey().getAlgorithm();
                System.out.println("Certificado: " + certificate);
                //Algoritmo Get public
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        });

        System.out.println("Ejercicio 2 ii ------------------------------------------------");
        // ii


        String password = "password";
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
        SecretKey secretKey = Xifrar.keygenKeyGeneration(256);

        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);

        try{
            KeyStore ks = Xifrar.loadKeyStore(keystoreTerminal,keystorePassword);
            ks.setEntry("millave",entry,protParam);
            FileOutputStream fos = new FileOutputStream(keystoreTerminal);
            ks.store(fos,keystorePassword.toCharArray());

        }catch (Exception e){
            e.printStackTrace();
        }

        System.out.println("Ejercicio 3  ------------------------------------------------");

        System.out.println(Xifrar.getPublicKey("jordi.cer"));

        KeyPair keyPair = Xifrar.randomGenerate(1024);

        System.out.println(keyPair.getPrivate().getAlgorithm());

        System.out.println("Ejercicio 4  ------------------------------------------------");

        System.out.println(Xifrar.getPublicKey(keyStore,"millave3","usuario"));

        System.out.println("Ejercicio 5  ------------------------------------------------");

        byte[] arraybyte = "Hola".getBytes(StandardCharsets.UTF_8);

        System.out.println(new String(Xifrar.signData(arraybyte, keyPair.getPrivate())));


    }
}
