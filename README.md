<h1 align="center">Cifra de Feistel</h1>

<p align="center">Atividade desenvolvida em Java durante a disciplina de Segurança em Sistemas de Computação <a href="https://sites.google.com/a/ice.ufjf.br/edelbertofranco/disciplinas/gradua%C3%A7%C3%A3o/2024-1-dcc075-seguran%C3%A7a?authuser=0">DCC075</a></p>

## Conceito

A Cifra de Feistel é uma estrutura ou design usado para desenvolver muitas cifras de bloco, como DES. A cifra Feistel pode ter componentes invertíveis, não invertíveis e autoinvertíveis em seu design. O mesmo algoritmo de criptografia e descriptografia é usado. Uma chave separada é usada para cada rodada. No entanto, as mesmas chaves redondas são usadas para criptografia e também para descriptografia. 

## Processo de Criptografia

O processo de criptografia utiliza a estrutura Feistel que consiste em múltiplas rodadas de processamento do texto simples, cada rodada consistindo em uma etapa de “substituição” seguida por uma etapa de permutação.

O bloco de entrada para cada rodada é dividido em duas metades que podem ser denotadas como L e R para a metade esquerda e a metade direita.

Em cada rodada, a metade direita do bloco, R, passa inalterada. Mas a metade esquerda, L, passa por uma operação que depende de R e da chave de criptografia. Primeiro, aplicamos uma função de criptografia 'f' que recebe duas entradas - as chaves K e R. A função produz a saída f(R,K). Então, fazemos um XOR na saída da função matemática com L.

Na implementação real da Cifra Feistel, como o DES, em vez de usar toda a chave de criptografia durante cada rodada, uma chave dependente da rodada (uma subchave) é derivada da chave de criptografia. Isso significa que cada rodada utiliza uma chave diferente, embora todas essas subchaves estejam relacionadas à chave original.

A etapa de permutação no final de cada rodada troca o L modificado e o R não modificado. Portanto, o L da próxima rodada seria o R da rodada atual. E R para a próxima rodada será a saída L da rodada atual.

As etapas acima de substituição e permutação formam uma 'rodada'. O número de rodadas é especificado pelo design do algoritmo.

Assim que a última rodada for concluída, os dois subblocos, 'R' e 'L', são concatenados nesta ordem para formar o bloco de texto cifrado.

<div align="center">
  <img src="https://www.tutorialspoint.com/cryptography/images/feistel_structure.jpg" alt="Cifra-Feistel" width="500" height="700">
</div>

