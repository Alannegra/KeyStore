package com.company;

import com.company.utils.Xifrar;

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
        String keystorePassword = "usuario";

        KeyStore keyStore = Xifrar.loadKeyStore(keystoreTerminal,keystorePassword);

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
                //Algoritmo Get public
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        });


        // ii
        KeyPair keyPair = Xifrar.randomGenerate(1024);
        System.out.println(keyPair.getPrivate().getAlgorithm());

        String password = "password";
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(keyPair.getS);
        try{
            KeyStore ks = Xifrar.loadKeyStore()
            ks.setEntry("millave",entry,protParam);
            FileOutputStream fos = new FileOutputStream();
            ks.store(fos,);

        }catch (Exception e){
            e.printStackTrace();
        }





    }
}
