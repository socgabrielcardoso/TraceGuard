# TraceGuard

Ferramenta de linha de comando para investigação de logs e geração de incidentes priorizados, criada com foco em análise defensiva, automação e operação de segurança.

O TraceGuard recebe registros de autenticação, aplica regras de análise e transforma eventos relevantes em uma saída estruturada, ajudando a separar ruído operacional de sinais que merecem investigação.

## Principais recursos

- Análise de logs de autenticação OpenSSH e entradas estruturadas com timestamp ISO e campos `key=value`.
- Geração de incidentes priorizados a partir de regras de detecção.
- Saída em texto ou JSON para uso humano ou integração com outros fluxos.
- Exportação de relatórios para arquivo.
- Filtro por severidade com `--fail-on`, útil em automações e pipelines.
- Comandos dedicados para listar regras, consultar versão e exibir ajuda.

A proposta é aproximar investigação de logs e automação: a ferramenta pode ser usada tanto manualmente por um analista quanto como etapa de validação em rotinas técnicas.

## Stack

- **Java 17**
- **Maven**
- **JUnit 5**
- Aplicação CLI empacotada como JAR executável

## Build

```bash
mvn clean package
```

## Exemplos de uso

```bash
traceguard analyze auth.log
traceguard analyze logs --format json --output incidents.json
traceguard analyze auth.log --fail-on high
traceguard rules
```

## Objetivo técnico

TraceGuard foi criado como projeto de Blue Team orientado a automação. O foco é demonstrar como eventos brutos podem ser normalizados, avaliados por regras e convertidos em incidentes acionáveis com severidade e saída previsível.

Além da análise manual, o código foi estruturado para facilitar integração futura com pipelines, coletores de logs, SIEMs e rotinas de resposta a incidentes.
