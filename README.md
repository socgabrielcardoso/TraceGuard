# TraceGuard

CLI em Java para transformar logs de autenticação em eventos normalizados e incidentes priorizados.

Criei o TraceGuard para praticar uma parte específica do trabalho de Blue Team: sair do log bruto, aplicar regras simples e chegar a uma saída que um analista consiga revisar sem precisar interpretar tudo manualmente.

## Recursos

- leitura de logs de autenticação OpenSSH
- suporte a entradas estruturadas com timestamp ISO e campos `key=value`
- normalização de eventos
- regras de detecção
- classificação por severidade
- saída em texto ou JSON
- exportação para arquivo
- `--fail-on` para uso em pipelines
- listagem de regras e informações de versão

## Stack

- Java 17
- Maven
- JUnit 5

## Build

```bash
mvn clean package
```

O artefato gerado fica em:

```text
target/traceguard.jar
```

## Exemplos

```bash
java -jar target/traceguard.jar analyze auth.log
java -jar target/traceguard.jar analyze logs --format json --output incidents.json
java -jar target/traceguard.jar analyze auth.log --fail-on high
java -jar target/traceguard.jar rules
```

## Estrutura

- `src/` — código Java
- `samples/` — exemplos de entrada
- `docs/` — arquitetura e notas técnicas
- `pom.xml` — build e dependências

## Limite do projeto

O TraceGuard não tenta ser um SIEM. É uma ferramenta pequena para estudar parsing, normalização, regras, severidade e saída estruturada de forma testável.
