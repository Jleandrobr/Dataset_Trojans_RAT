import requests
import sys
import pyzipper
import pandas as pd
import os
import time

def request_malware_bazaar(data, headers):
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=60, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.HTTPError as http_err:
        print(f"[ERROR] HTTP error occurred: {http_err} - {response.text}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] API request failed: {e}")
        sys.exit(1)

def extract_zip(file_name, password, extract_path):
    try:
        with pyzipper.AESZipFile(file_name) as zf:
            zf.pwd = password
            zf.extractall(extract_path)
            print(f"Sample '{file_name}' extracted successfully in '{extract_path}'.")
    except Exception as e:
        print(f"[ERROR] Failed to extract ZIP: {e}")

def main():
    PLANILHA = 'rats.xlsx'      # nome da planilha
    COLUNA_HASH = 'sha256_hash'  # nome da coluna da hash
    API_KEY = ''  # sua API KEY
    LIMITE_DIARIO = 1000
    PASTA_MALWARE = 'malware'    # nome da pasta para os arquivos extraidos

    os.makedirs(PASTA_MALWARE, exist_ok=True)

    #carrega os hashes (removendo duplicatas e nulos)
    df = pd.read_excel(PLANILHA)
    todas_hashes = df[COLUNA_HASH].dropna().astype(str).drop_duplicates().tolist()

    # le os hashs já baixados
    baixadas = set()
    try:
        with open('baixadas.txt', 'r') as f:
            baixadas = set(line.strip() for line in f)
    except FileNotFoundError:
        pass

    headers = {
        'Auth-Key': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    ZIP_PASSWORD = b'infected'
    baixadas_hoje = 0

    for sha256 in todas_hashes:
        if baixadas_hoje >= LIMITE_DIARIO:
            print(f"Limite de {LIMITE_DIARIO} downloads alcançado. Rode novamente amanhã.")
            break
        if sha256 in baixadas:
            continue
        data = {'query': 'get_file', 'sha256_hash': sha256}
        response = request_malware_bazaar(data, headers)
        if 'file_not_found' in response.text:
            print(f"[ERROR] File not found: {sha256}")
            continue
        file_name = os.path.join(PASTA_MALWARE, sha256 + '.zip')
        with open(file_name, 'wb') as f:
            f.write(response.content)
        print(f"Sample '{sha256}' downloaded to {file_name}.")

        extract_zip(file_name, ZIP_PASSWORD, PASTA_MALWARE)

        with open('baixadas.txt', 'a') as f:
            f.write(sha256 + '\n')
        baixadas_hoje += 1
        # Pra evitar overload (opcional): time.sleep(1)

if __name__ == "__main__":
    main()
