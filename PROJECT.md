# TraceGuard — notas do projeto

## Problema

Logs de autenticação costumam chegar como texto bruto. O TraceGuard organiza esse conteúdo em eventos normalizados e executa regras simples para destacar o que merece revisão.

## Fluxo

1. lê o arquivo de entrada;
2. interpreta cada registro;
3. normaliza os campos;
4. executa regras de detecção;
5. classifica o resultado;
6. entrega saída em texto ou JSON.

## Tecnologias

- Java 17
- Maven
- JUnit 5

## Uso esperado

O projeto serve para estudar parsing, regras, severidade, correlação e automação defensiva em uma base pequena o suficiente para entender todo o fluxo.
