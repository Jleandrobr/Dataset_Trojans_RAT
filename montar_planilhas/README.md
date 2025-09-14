# Documentação: Montar Planilhas a partir das análises do pescanner

**Repositório referenciado:** https://github.com/Jheklos/Projeto

---

## Objetivo
Esta documentação descreve como montar planilhas (agregar metadados) a partir dos relatórios textuais gerados pelo `pescanner.py`. O processo organiza os arquivos gerados em uma estrutura de pastas específica e executa o script principal `montar_planilhas.py`, que utiliza os módulos auxiliares `PegaDlls.py`, `PegaIAT.py` e `PegaResource.py` para extrair campos relevantes.

---

## Estrutura de pastas esperada
```
montar_planilhas/
├── montar_planilhas.py
├── PegaDlls.py
├── PegaIAT.py
├── PegaResource.py
../
└── analises_pescanner/
    └── APT/
        ├── benign/
        │   └── analysis/
        │       ├── benign1.txt
        │       └── benign2.txt
        └── malware/
            └── analysis/
                ├── malware1.txt
                └── malware2.txt
```

---

## Como criar a estrutura de diretórios
Dentro da pasta `montar_planilhas`, execute os comandos abaixo para criar as pastas de entrada onde o `pescanner.py` deve ter gravado seus relatórios:

```bash
mkdir -p ../analises_pescanner/APT/benign/analysis
mkdir -p ../analises_pescanner/APT/malware/analysis
```

---

## Onde colocar os arquivos de entrada
- Copie/ mova os arquivos `.txt` gerados pelo `pescanner.py` para as pastas:
  - `../analises_pescanner/APT/benign/analysis/`
  - `../analises_pescanner/APT/malware/analysis/`

Cada arquivo `.txt` deve conter o relatório estático de um executável (PE) gerado pelo `pescanner`.

---

## ATENÇÃO
**Para gerar uma base autoral será necessário coletar amostras benignas para o PE Scanner analisá-las.**

- As amostras benignas são importantes para criar um conjunto de referência e balancear a base entre benignos e maliciosos.
- Garanta que as amostras benignas sejam obtidas de fontes confiáveis e que não contenham PII ou componentes proprietários não autorizados.
- Mantenha as amostras benignas em ambiente isolado e com controle de acesso, assim como as amostras maliciosas.

---

## Executando o pipeline de montagem de planilhas
Com a estrutura de pastas pronta e os arquivos `.txt` em seus devidos lugares, rode o script principal:

```bash
cd montar_planilhas
python3 montar_planilhas.py
```

### O que o script faz (comportamento esperado)
- Varre as pastas `benign/analysis` e `malware/analysis` em busca de arquivos `.txt`.
- Para cada relatório encontrado, utiliza os módulos auxiliares para extrair campos específicos:
  - `PegaDlls.py`: extrai DLLs referenciadas/importadas.
  - `PegaIAT.py`: extrai entradas da Import Address Table (IAT) e imports utilizados.
  - `PegaResource.py`: extrai recursos embutidos (strings, recursos binários, etc.).
- Consolida os campos extraídos em uma ou mais planilhas (CSV/Excel) prontas para análise.

---

## Referências
- Repositório base: https://github.com/Jheklos/Projeto

---
