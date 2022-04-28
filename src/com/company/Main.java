package com.company;

import com.company.utils.Xifrar;

import java.security.KeyPair;
import java.util.Scanner;

public class Main {
    //Genera un parell de claus (KeyPair) de 1024bits, i utilitza-les per xifrar i desxifrar un missatge.

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        System.out.println("Escribe el mensaje a encriptar: ");
        String missatge = scanner.nextLine();

        byte[] byteArrray = missatge.getBytes();
        KeyPair keyPair = Xifrar.randomGenerate(1024);

        //String encriptat = new String(Xifrar.encryptData(byteArrray,keyPair.getPublic()));

        byte[] encriptat = Xifrar.encryptData(byteArrray,keyPair.getPublic());

        String desencriptat = new String(Xifrar.dencryptData(encriptat,keyPair.getPrivate()));

        System.out.println(desencriptat);

        System.out.println(keyPair.getPublic().getAlgorithm());
        System.out.println(keyPair.getPublic().getEncoded());
        System.out.println(keyPair.getPublic().getClass());
        System.out.println(keyPair.getPublic().getFormat());

        System.out.println(keyPair.getPrivate().getAlgorithm());
        System.out.println(keyPair.getPrivate().getEncoded());
        System.out.println(keyPair.getPrivate().getClass());
        System.out.println(keyPair.getPrivate().getFormat());









    }
}
