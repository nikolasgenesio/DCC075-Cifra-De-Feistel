package org.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class FeistelCipher {
    // S-Boxes (https://en.wikipedia.org/wiki/DES_supplementary_material)
    static int[][][] sbox = {
            // S1
            {
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            // S2
            {
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            // S3
            {
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            // S4
            {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            // S5
            {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            // S6
            {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            // S7
            {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            // S8
            {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
    };

    // Função de encriptação
    public static String encriptacao(String texto, String chave) {
        byte[] pt_Bytes = texto.getBytes(StandardCharsets.UTF_8);
        byte[] chave_Bytes = gerarChave(chave);

        int tamanho_bloco = pt_Bytes.length / 2;
        int[] esquerda = new int[tamanho_bloco];
        int[] direita = new int[tamanho_bloco];

        // Dividindo o texto em blocos de esquerda e direita
        for (int i = 0; i < tamanho_bloco; i++) {
            esquerda[i] = pt_Bytes[i];
            direita[i] = pt_Bytes[i + tamanho_bloco];
        }

        // Realizando as 16 rodadas de Feistel
        for (int i = 0; i < 16; i++) {
            int[] temp = Arrays.copyOf(direita, direita.length);
            int[] f_saida = f(direita, chave_Bytes[i]);

            // XOR do resultado da função f com o bloco de esquerda
            for (int j = 0; j < tamanho_bloco; j++) {
                direita[j] = esquerda[j] ^ f_saida[j];
            }

            // O bloco de direita se torna o bloco de esquerda da próxima rodada
            esquerda = Arrays.copyOf(temp, temp.length);
        }

        // Concatenando os blocos de esquerda e direita e convertendo para string hexadecimal
        StringBuilder texto_cifrado = new StringBuilder();
        for (int i = 0; i < tamanho_bloco; i++) {
            texto_cifrado.append(Integer.toHexString(esquerda[i]));
            texto_cifrado.append(Integer.toHexString(direita[i]));
        }

        return texto_cifrado.toString();
    }

    // Função F que utiliza as caixas S-Box DES
    public static int[] f(int[] bloco, byte chave) {
        int[] saida = new int[bloco.length];
        int expansao_bloco = expansaoBloco(bloco);
        int resultado_xor = expansao_bloco ^ chave;
        int[] sBox_saida = sBoxSubstituicao(resultado_xor);
        saida = permutacao(sBox_saida);
        return saida;
    }

    // Expansão do bloco
    public static int expansaoBloco(int[] bloco) {
        int expansao_bloco = 0;
        for (int i = 0; i < bloco.length; i++) {
            expansao_bloco = (expansao_bloco << 8) | bloco[i];
        }
        return expansao_bloco;
    }

    // Substituição utilizando as caixas S-Box
    public static int[] sBoxSubstituicao(int bloco) {
        int[] saida = new int[8];
        for (int i = 0; i < 8; i++) {
            int linha = ((bloco & 0x80) >> 6) | ((bloco & 0x04) >> 2);
            int coluna = (bloco & 0x78) >> 3;
            saida[i] = sbox[i][linha][coluna];
            bloco <<= 4;
        }
        return saida;
    }

    // Permutação
    public static int[] permutacao(int[] entrada) {
        int[] saida = new int[entrada.length];
        for (int i = 0; i < entrada.length; i++) {
            saida[i] = entrada[(i + 1) % entrada.length];
        }
        return saida;
    }

    // Gera uma chave a partir da chave original
    public static byte[] gerarChave(String chave) {
        byte[] chave_Bytes = new byte[16];
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] mdBytes = md.digest(chave.getBytes());
            System.arraycopy(mdBytes, 0, chave_Bytes, 0, Math.min(mdBytes.length, chave_Bytes.length));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return chave_Bytes;
    }

}