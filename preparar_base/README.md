# README: Converter CSV → LIBSVM (para SVM)

**Repositório referenciado:** https://github.com/Jheklos/Projeto.git

---

## Objetivo
Este README descreve como usar o script `converter_libsvm.py` para transformar um arquivo CSV em formato **LIBSVM**, pronto para treinar um classificador SVM.

---

## Uso
Coloque o arquivo CSV na mesma pasta do script ou informe o caminho completo. Em seguida execute um dos comandos abaixo:

### CSV na mesma pasta do script
```bash
python converter_libsvm.py AQUI_o_ARQUIVO.csv NOME_CSV.libsvm
```

### CSV em outra pasta (caminho completo)
```bash
python converter_libsvm.py /caminho/para/AQUI_o_ARQUIVO.csv /caminho/para/NOME_CSV.libsvm
```

---

## ATENÇÃO
**É NECESSÁRIO juntar as planilhas `malware` e `benign` que irão compor a base antes de executar a conversão.**

- Garanta que as colunas estejam alinhadas (mesma ordem e nomes) entre as planilhas de malware e benignos.
- Defina claramente a coluna de rótulo (label) — geralmente a primeira coluna — contendo valores como `1` (malware) e `0` (benigno) ou outra convenção consistente suportada pelo seu pipeline de treino.
- Faça limpeza/normalização de valores (valores ausentes, tipos não-numéricos, codificação) antes da conversão.

---

## Recomendações
- Verifique o cabeçalho do CSV.
- Faça backup do CSV original antes da conversão.

---
