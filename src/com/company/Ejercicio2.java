package com.company;

import com.company.utils.Xifrar;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

public class Ejercicio2 {
    public static void main(String[] args) throws Exception {

        String keystoreTerminal = "../../keystore_abril.ks";
        String keystorePassword = "usuario";

        KeyStore keyStore = Xifrar.loadKeyStore(keystoreTerminal,keystorePassword);


//        Mida del magatzem (quantes claus hi ha?)
//        Àlies de totes les claus emmagatzemades
//        El certificat d’una de les claus
//        L'algorisme de xifrat d’alguna de les claus

        //System.out.println(new String(keystore.getBytes(), StandardCharsets.UTF_8));

        System.out.println(keyStore.getType());
        System.out.println(keyStore.size());

        Enumeration<String> a = keyStore.aliases();
        Collections.list(a).forEach(o -> {
            System.out.println(o);
            try {
                System.out.println(keyStore.getCertificateChain(o));
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        });





    }
}
