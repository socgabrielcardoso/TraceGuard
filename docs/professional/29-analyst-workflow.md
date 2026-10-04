# Fluxo de análise

Quando o TraceGuard gera um incidente:

1. começar pelos itens de maior severidade;
2. conferir quais eventos fizeram a regra disparar;
3. voltar ao log bruto;
4. validar usuário, origem e horário;
5. comparar com outros eventos próximos;
6. decidir se o comportamento é esperado, suspeito ou confirmado;
7. registrar o motivo;
8. ajustar a regra apenas se o padrão for repetível.

A saída da ferramenta é ponto de partida. A decisão ainda depende do contexto.
