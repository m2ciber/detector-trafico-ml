import os

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

RUTA_TRAIN = "datos/KDDTrain+.txt"
RUTA_TEST = "datos/KDDTest+.txt"

CARACTERISTICAS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAS = ["protocol_type", "service", "flag"]

# El archivo de entrenamiento trae etiqueta + dificultad; el de prueba, solo etiqueta
COLUMNAS_TRAIN = CARACTERISTICAS + ["label", "difficulty"]
COLUMNAS_TEST = CARACTERISTICAS + ["label"]

# Cada ataque concreto se agrupa en su familia
FAMILIAS = {
    "DoS": ["back", "land", "neptune", "pod", "smurf", "teardrop", "apache2",
            "udpstorm", "processtable", "worm", "mailbomb"],
    "Probe": ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"],
    "R2L": ["guess_passwd", "ftp_write", "imap", "phf", "multihop",
            "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
            "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"],
    "U2R": ["buffer_overflow", "loadmodule", "rootkit", "perl", "sqlattack",
            "xterm", "ps"],
}
ATAQUE_A_FAMILIA = {a: fam for fam, lista in FAMILIAS.items() for a in lista}


def leer(ruta, columnas):
    if not os.path.exists(ruta):
        raise SystemExit(f"[ERROR] No encuentro {ruta}. Revisa la carpeta 'datos'.")
    df = pd.read_csv(ruta, header=None, names=columnas, sep=r"\s+")
    X = df[CARACTERISTICAS]
    etiqueta = df["label"].astype(str).str.strip().str.lower()
    return X, etiqueta


def a_binario(etiqueta):
    return etiqueta.map(lambda x: "Normal" if x == "normal" else "Ataque")


def a_familia(etiqueta):
    return etiqueta.map(lambda x: "Normal" if x == "normal" else ATAQUE_A_FAMILIA.get(x, "Otro"))


def crear_modelo():
    return Pipeline([
        ("prep", ColumnTransformer(
            [("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAS)],
            remainder="passthrough",
        )),
        ("rf", RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)),
    ])


def exigir_dos_clases(serie, nombre):
    if serie.nunique() < 2:
        raise SystemExit(
            f"[ERROR] {nombre} solo tiene una clase: {serie.unique()}. "
            "Revisa el formato del archivo antes de seguir."
        )


if __name__ == "__main__":
    print("[*] Cargando datos reales NSL-KDD...")
    X_train, etq_train = leer(RUTA_TRAIN, COLUMNAS_TRAIN)
    X_test, etq_test = leer(RUTA_TEST, COLUMNAS_TEST)
    print(f"    Entrenamiento: {len(X_train)} registros | Prueba: {len(X_test)} registros")

    y_train_bin = a_binario(etq_train)
    y_test_bin = a_binario(etq_test)
    exigir_dos_clases(y_train_bin, "El entrenamiento")
    exigir_dos_clases(y_test_bin, "La prueba")

    print("\nDistribución (Normal / Ataque):")
    print("  Entrenamiento:", y_train_bin.value_counts().to_dict())
    print("  Prueba:       ", y_test_bin.value_counts().to_dict())

    # ---------- PARTE A: medición oficial, binaria ----------
    print("\n[*] PARTE A: entrenando con KDDTrain+ y probando con KDDTest+ ...")
    modelo = crear_modelo()
    modelo.fit(X_train, y_train_bin)
    pred = modelo.predict(X_test)
    clases = ["Normal", "Ataque"]
    print("\n=== PARTE A: INFORME EN KDDTest+ (oficial, binario) ===")
    print(classification_report(y_test_bin, pred, labels=clases, zero_division=0))
    print("Matriz de confusión (filas = real, columnas = predicho), orden", clases)
    print(confusion_matrix(y_test_bin, pred, labels=clases))

    os.makedirs("modelos", exist_ok=True)
    joblib.dump(modelo, "modelos/ids_nslkdd.joblib")
    print("\n[+] Modelo guardado en modelos/ids_nslkdd.joblib")

    # ---------- PARTE B: por familias, dentro del entrenamiento ----------
    y_fam = a_familia(etq_train)
    desconocidas = sorted(set(etq_train[y_fam == "Otro"]))
    if desconocidas:
        print("\n[AVISO] Ataques no clasificados en ninguna familia:", desconocidas)

    print("\nFamilias en el entrenamiento:", y_fam.value_counts().to_dict())
    X_a, X_b, y_a, y_b = train_test_split(
        X_train, y_fam, test_size=0.25, random_state=42, stratify=y_fam
    )
    print("\n[*] PARTE B: entrenando con el 75 % de KDDTrain+ ...")
    modelo_fam = crear_modelo()
    modelo_fam.fit(X_a, y_a)
    pred_b = modelo_fam.predict(X_b)
    etiquetas = sorted(y_fam.unique())
    print("\n=== PARTE B: INFORME POR FAMILIAS (25 % reservado de KDDTrain+) ===")
    print("Aviso: es más optimista que la parte A, porque los ataques son del mismo tipo que en el entrenamiento.")
    print(classification_report(y_b, pred_b, labels=etiquetas, zero_division=0))
    print("Matriz de confusión (filas = real, columnas = predicho), orden", etiquetas)
    print(confusion_matrix(y_b, pred_b, labels=etiquetas))