import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

np.random.seed(42)

NOMBRES_CLASES = ["Normal", "Port Scan", "Fuerza bruta SSH", "DDoS"]


def generar_dataset_sintetico(n_muestras=3000):
    """Genera flujos de red sintéticos: 0=normal, 1=port scan, 2=SSH, 3=DDoS."""
    filas = []
    for _ in range(n_muestras):
        tipo = np.random.choice([0, 1, 2, 3], p=[0.6, 0.15, 0.15, 0.10])

        if tipo == 0:  # Tráfico normal (navegación web, DNS)
            duracion = np.random.uniform(1.0, 60.0)
            paquetes = np.random.randint(10, 500)
            bytes_totales = paquetes * np.random.randint(400, 1400)
            puerto = np.random.choice([80, 443, 53])
            syn = np.random.randint(1, 3)
        elif tipo == 1:  # Escaneo de puertos (tipo Nmap SYN scan)
            duracion = np.random.uniform(0.001, 0.05)
            paquetes = np.random.randint(1, 3)
            bytes_totales = paquetes * 60
            puerto = np.random.randint(1, 65535)
            syn = 1
        elif tipo == 2:  # Fuerza bruta SSH
            duracion = np.random.uniform(0.5, 3.0)
            paquetes = np.random.randint(15, 40)
            bytes_totales = paquetes * np.random.randint(80, 150)
            puerto = 22
            syn = 1
        else:  # DDoS (SYN flood)
            duracion = np.random.uniform(0.01, 0.5)
            paquetes = np.random.randint(1000, 10000)
            bytes_totales = paquetes * 64
            puerto = np.random.choice([80, 443])
            syn = paquetes

        filas.append([duracion, paquetes, bytes_totales, puerto, syn, tipo])

    columnas = ["duracion", "paquetes", "bytes_totales", "puerto_destino", "flags_syn", "etiqueta"]
    return pd.DataFrame(filas, columns=columnas)


if __name__ == "__main__":
    print("[*] Generando dataset sintético de tráfico de red...")
    df = generar_dataset_sintetico(3000)

    X = df.drop("etiqueta", axis=1)
    y = df["etiqueta"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print("[*] Entrenando modelo Random Forest...")
    modelo = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    modelo.fit(X_train, y_train)

    predicciones = modelo.predict(X_test)

    print("\n=== INFORME DE CLASIFICACIÓN ===")
    print(classification_report(y_test, predicciones, target_names=NOMBRES_CLASES))

    print("=== MATRIZ DE CONFUSIÓN ===")
    print(confusion_matrix(y_test, predicciones))

    print("\n=== IMPORTANCIA DE CADA CARACTERÍSTICA ===")
    for nombre, valor in sorted(zip(X.columns, modelo.feature_importances_), key=lambda p: -p[1]):
        print(f"  {nombre}: {valor:.3f}")

    os.makedirs("modelos", exist_ok=True)
    joblib.dump(modelo, "modelos/ids_random_forest.joblib")
    print("\n[+] Modelo guardado en modelos/ids_random_forest.joblib")