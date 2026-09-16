# TraceGuard

> **Blue Team Security Lab** — laboratório pessoal para estudo prático de análise de logs, detecção e automação defensiva.

O **TraceGuard** é uma ferramenta de linha de comando criada para transformar registros de autenticação em eventos estruturados e incidentes priorizados. O projeto explora fundamentos de operações defensivas, investigação de logs e automação com foco em clareza, rastreabilidade e integração futura com fluxos de segurança.

## Foco técnico

- Análise de logs de autenticação OpenSSH e entradas estruturadas com timestamp ISO e campos `key=value`.
- Normalização de eventos e aplicação de regras de detecção.
- Geração de incidentes priorizados por severidade.
- Saída em texto ou JSON para análise humana e automações.
- Exportação de resultados para arquivo.
- Filtro por severidade com `--fail-on`, útil em pipelines e rotinas técnicas.
- Comandos dedicados para listar regras, consultar versão e exibir ajuda.

## Contexto de estudo

O projeto foi criado como laboratório de **Blue Team / SOC** para praticar o caminho entre um evento bruto e uma saída acionável: coleta, normalização, avaliação por regra, classificação e priorização.

Não busca substituir um SIEM ou uma plataforma de SOC. A proposta é estudar, em uma base controlada, conceitos que aparecem em ferramentas e operações reais de segurança.

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

## Evolução possível

A arquitetura permite evoluções como integração com coletores de logs, SIEMs, pipelines de validação, novas regras de detecção e rotinas de resposta a incidentes.

---

**Categoria:** Cybersecurity • Blue Team • Log Analysis • Detection Engineering • Automation

**Status:** laboratório pessoal de estudo e experimentação técnica.
