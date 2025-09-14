# Projeto de Base Autoral para Análise de Malware

## Objetivo
Este repositório documenta o processo completo para **criação de uma base autoral de amostras de malware e benignos** para análises em **cybersecurity**. O processo contempla desde a coleta de amostras até a conversão em formatos adequados para treinamento de modelos de Machine Learning (ex: SVM).

---

## Estrutura do Projeto

1. **Coleta de amostras no MalwareBazaar**  
   - Utiliza script `bazaar_download_remake.py` para baixar amostras a partir de hashes SHA256 listados em planilha.  
   - Referência: [Projeto (Jheklos)](https://github.com/Jheklos/Projeto)

2. **Filtragem de executáveis**  
   - Uso do script `find_exec.py` (do repositório [VirusTotalAPI](https://github.com/DejavuForensics/VirusTotalAPI.git)).  
   - Isola executáveis Windows (PE) para análise estática.

3. **Análise Estática com Pescanner**  
   - Executar `pescanner.py` para analisar cada executável.  
   - Resultados armazenados em `analises_malware/`.

4. **Montagem das Planilhas**  
   - Estrutura organizada em `analises_pescanner/APT/{benign,malware}/analysis/`.  
   - Scripts principais: `montar_planilhas.py`, `PegaDlls.py`, `PegaIAT.py`, `PegaResource.py`.  
   - Referência: [Projeto (Jheklos)](https://github.com/Jheklos/Projeto)

5. **Conversão para LIBSVM**  
   - Uso de `converter_libsvm.py` para preparar os datasets em formato aceito por classificadores SVM.  
   - **Importante:** antes da conversão, juntar as planilhas de `malware` e `benign`.

---

## Pré-requisitos
- Python 3.x
- `pip install -r requirements.txt`
- Ambiente virtual recomendado:
```bash
python -m venv venv
source venv/bin/activate
```

---

## Estrutura de Pastas Recomendada
```
├── download_amostras/
│ └── bazaar_download_remake.py
├── analise_estatica/
│ ├── find_exec.py
│ └── pescanner.py
├── montar_planilhas/
│ ├── montar_planilhas.py
│ ├── PegaDlls.py
│ ├── PegaIAT.py
│ └── PegaResource.py
├── analises_pescanner/
│ └── APT/
│ ├── benign/analysis/
│ └── malware/analysis/
├── preparar_base/
│ └── converter_libsvm.py
└── README.md (este arquivo)
```

---

## ATENÇÃO
- Para gerar uma **base autoral** é necessário coletar amostras **malware** e também **benignas**.
- Os arquivos benignos devem passar igualmente pelo `pescanner.py` para compor a base balanceada.
- Certifique-se de alinhar colunas entre as planilhas antes da conversão para LIBSVM.

---

## Referências
- Projeto base: [Jheklos/Projeto](https://github.com/Jheklos/Projeto)
- Script find_exec: [DejavuForensics/VirusTotalAPI](https://github.com/DejavuForensics/VirusTotalAPI.git)

