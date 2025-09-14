# Documentação: Baixar amostras do MalwareBazaar

**Repositório referenciado:** https://github.com/Jheklos/Projeto

---

## Resumo
Esta seção descreve, em formato passo a passo, o procedimento para baixar amostras do MalwareBazaar usando o script `bazaar_download_remake.py` adaptado para ler uma planilha contendo hashes SHA256. O objetivo é alimentar sua base de dados autoral de amostras/metadados para análise de malware, controlando downloads já realizados com um arquivo `baixadas.txt`.

> Observação de segurança: execute todo o processo dentro de um ambiente isolado (VMs dedicadas, rede segmentada ou air-gapped). Não execute amostras em hosts de produção e mantenha snapshots para rollback.

---

## Pré-requisitos
- Conta/credenciais ou chave de API do MalwareBazaar.
- Acesso ao repositório referenciado: `https://github.com/Jheklos/Projeto` — use-o como base/teste.
- Python 3.8+ instalado no host de análise.
- Arquivo de planilha (CSV/XLSX) contendo, pelo menos, uma coluna `sha256` com os hashes das amostras a baixar.

---

## Estrutura de pastas recomendada
```
/projeto/
├─ bazaar_download_remake.py
├─ requirements.txt
├─ amostras_planilha.csv   # ou .xlsx
├─ baixadas.txt            # criado automaticamente após o primeiro download
├─ venv/                   # virtualenv
└─ malware/                # onde as amostras baixadas serão salvas
```

---

## Passo a passo (comandos)
1. Clone o repositório de referência (opcional):

```bash
git clone https://github.com/Jheklos/Projeto
cd Projeto
```

2. Crie o ambiente virtual Python:

```bash
python -m venv venv
```

3. Ative o ambiente virtual:

- Linux / macOS (bash/zsh):

```bash
source venv/bin/activate
```

- Windows (PowerShell):

```powershell
venv\Scripts\Activate.ps1
```


4. Instale dependências:

```bash
pip install -r requirements.txt
```

5. Coloque a planilha com os hashes (coluna `sha256`) na mesma pasta do script `bazaar_download_remake.py`. Exemplos de nomes: `amostras.csv`, `amostras.xlsx`.

6. Execute o script (ex.:)

```bash
python bazaar_download_remake.py
```


7. Controle de amostras baixadas

- O script gera (ou atualiza) um arquivo `baixadas.txt` contendo a lista de hashes já baixados. Isso evita re-downloads em caso de falhas na API ou reinício do processo.
- Exemplo de conteúdo de `baixadas.txt`:
```
3a7e9f... (sha256)
b1c4d2... (sha256)
```

---

## Comportamento esperado do script
- O script lê os hashes (`sha256`) da planilha.
- Para cada hash, consulta o MalwareBazaar e, se disponível, realiza o download do binário correspondente para a pasta `malware/`.
- Ao concluir o download com sucesso, o hash é gravado/confirmado no `baixadas.txt`.
- Em caso de erro (timeout, quota da API, resposta inválida), o script registra a falha em logs e continua com os próximos hashes permitindo reexecução posterior sem rebaixar o que já consta em `baixadas.txt`.


---

## Referências
- Repositório base: https://github.com/Jheklos/Projeto



