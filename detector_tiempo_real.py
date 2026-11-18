import time

import joblib
import pandas as pd

CLASES = {
    0: ("TRÁFICO NORMAL", "INFO"),
    1: ("ESCANEO DE PUERTOS (posible Nmap)", "ALERTA MEDIA"),
    2: ("INTENTO DE FUERZA BRUTA SSH", "ALERTA ALTA"),
    3: ("ATAQUE DDoS (SYN flood)", "CRÍTICO"),
}

COLUMNAS = ["duracion", "paquetes", "bytes_totales", "puerto_destino", "flags_syn"]


def simular_trafico():
    """Cinco flujos inventados: [duracion, paquetes, bytes, puerto, flags_syn]."""
    flujos = [
        [15.4, 120, 85000, 443, 1],       # navegación HTTPS normal
        [0.004, 1, 60, 8080, 1],          # sondeo a un puerto
        [1.2, 25, 2800, 22, 1],           # ráfaga contra SSH
        [0.15, 5400, 345600, 80, 5400],   # inundación de SYN
        [8.2, 45, 32000, 443, 1],         # navegación HTTPS normal
    ]
    return pd.DataFrame(flujos, columns=COLUMNAS)


if __name__ == "__main__":
    modelo = joblib.load("modelos/ids_random_forest.joblib")
    flujos = simular_trafico()

    print("[*] Iniciando monitorización IDS con Machine Learning (simulada)...\n")
    for i in range(len(flujos)):
        muestra = flujos.iloc[[i]]
        clase = int(modelo.predict(muestra)[0])
        confianza = modelo.predict_proba(muestra)[0].max() * 100
        descripcion, severidad = CLASES[clase]

        puerto = int(muestra["puerto_destino"].iloc[0])
        paquetes = int(muestra["paquetes"].iloc[0])
        print(
            f"[Flujo #{i + 1}] Puerto {puerto} | Paquetes {paquetes} -> "
            f"[{severidad}] {descripcion} (confianza {confianza:.1f}%)"
        )
        time.sleep(1)