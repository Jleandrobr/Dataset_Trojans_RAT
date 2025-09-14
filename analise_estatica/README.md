# Documentação: Análise Estática de Executáveis (find_exec.py → pescanner.py)

**Repositório de origem do script find_exec.py:** https://github.com/DejavuForensics/VirusTotalAPI.git

---

## Resumo
Este documento descreve um fluxo separado e independente para realizar análise estática de executáveis Windows coletados anteriormente via MalwareBazaar. O script `find_exec.py` do repositório referenciado é utilizado para localizar/extrair os binários coletados, que em seguida são processados pelo analisador `pescanner.py`. O resultado das análises é salvo em uma pasta `analises_malware/`.

> Segurança: execute todo o processo em uma máquina ou VM isolada. Não execute binários fora de ambientes de análise controlados.

---

## Pré-requisitos
- Clone do repositório que contém `find_exec.py` (fonte): `https://github.com/DejavuForensics/VirusTotalAPI.git`.
- Script `pescanner.py` (analisador estático de executáveis Windows) disponível no mesmo diretório..
- Pasta com as amostras baixadas (por exemplo, a pasta `malware/` do processo anterior com os binários do MalwareBazaar).

---

## Estrutura de pastas recomendada
```
/analise_estatica/
├─ find_exec.py            # originado de VirusTotalAPI repo
├─ pescanner.py            # analisador estático
├─ malwares/                # amostras baixadas
└─ analises_malware/       # saída gerada pelo pescanner
```

---

## Passo a passo (comandos)


1. Coloque `find_exec.py` e `pescanner.py` no mesmo diretório de trabalho ou ajuste paths conforme necessário dentro dos códigos.


2. Garanta que a pasta `malwares/` (ou a pasta onde os binários estão) contenha os executáveis a serem analisados.

3. Rode o analisador (exemplo):

```bash
python pescanner.py
```

4. Verifique a saída

- Ao término, será criada/atualizada a pasta `analises_malware/` contendo os resultados produzidos pelo `pescanner.py`.

---

## Comportamento esperado
- `find_exec.py` localiza e lista/extrai executáveis (PE) a partir da estrutura de amostras fornecida.
- `pescanner.py` analisa cada executável estaticamente: cabeçalhos PE, imports, seções, strings, assinaturas, heurísticas e possíveis indicadores de comprometimento.
- Resultados em `analises_malware/` podem conter JSON ou arquivos de texto com os relatórios por amostra.


---

## Referências
- Script fonte: https://github.com/DejavuForensics/VirusTotalAPI.git

---
