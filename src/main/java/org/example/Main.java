package org.example;

import java.util.Scanner;

import static org.example.FeistelCipher.*;

public class Main {
    public static void main(String[] args) {
        Scanner entrada = new Scanner(System.in);
        System.out.println("Digite o texto a ser encriptado: ");
        String texto = entrada.next();
        System.out.println("Digite a chave: ");
        String chave = entrada.next();
        String cifra = encriptacao(texto, chave);
        System.out.println("Texto cifrado: " + cifra);
    }
}