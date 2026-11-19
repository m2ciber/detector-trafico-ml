import numpy as np

from entrenar_nslkdd import (
    COLUMNAS_TEST, COLUMNAS_TRAIN, RUTA_TEST, RUTA_TRAIN,
    a_binario, crear_modelo, leer,
)

# Ataques que NO se usan para entrenar el modelo de validación: simulan ataques nuevos
RESERVADOS = ["ipsweep", "teardrop", "warezclient", "guess_passwd", "satan"]
OBJETIVO_RECALL = 0.90
UMBRALES = [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05]


def probabilidad_ataque(modelo, X):
    clases = list(modelo.named_steps["rf"].classes_)
    return modelo.predict_proba(X)[:, clases.index("Ataque")]


def medir(y_real, proba, umbral):
    real = (y_real == "Ataque").to_numpy()
    pred = proba >= umbral
    tp = int((pred & real).sum())
    fn = int((~pred & real).sum())
    fp = int((pred & ~real).sum())
    tn = int((~pred & ~real).sum())
    return {
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "falsas": fp / (fp + tn) if fp + tn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "acierto": (tp + tn) / len(real),
        "matriz": (tn, fp, fn, tp),
    }


def mostrar(titulo, y_real, proba):
    print(f"\n{titulo}")
    print("umbral | ataques detectados | falsas alarmas | precisión | acierto")
    for u in UMBRALES:
        m = medir(y_real, proba, u)
        print(f"  {u:<5} | {m['recall']:>18.1%} | {m['falsas']:>14.1%} | {m['precision']:>9.1%} | {m['acierto']:>7.1%}")


if __name__ == "__main__":
    print("[*] Cargando datos...")
    X_train, etq_train = leer(RUTA_TRAIN, COLUMNAS_TRAIN)
    X_test, etq_test = leer(RUTA_TEST, COLUMNAS_TEST)
    y_test = a_binario(etq_test)

    # 1) Validación con ataques "nuevos": se reservan algunos tipos de ataque y el 25 % del tráfico normal
    rng = np.random.RandomState(42)
    es_normal = (etq_train == "normal").to_numpy()
    a_validacion = (es_normal & (rng.rand(len(etq_train)) < 0.25)) | etq_train.isin(RESERVADOS).to_numpy()

    X_a, y_a = X_train[~a_validacion], a_binario(etq_train[~a_validacion])
    X_v, y_v = X_train[a_validacion], a_binario(etq_train[a_validacion])
    print(f"    Entrenamiento: {len(X_a)} registros | Validación: {len(X_v)} registros")
    print("    Validación:", y_v.value_counts().to_dict())

    print("[*] Entrenando el modelo de validación (puede tardar un minuto)...")
    modelo_val = crear_modelo()
    modelo_val.fit(X_a, y_a)
    p_val = probabilidad_ataque(modelo_val, X_v)
    mostrar("VALIDACIÓN: ataques reservados, no vistos en el entrenamiento", y_v, p_val)

    elegido = None
    for u in UMBRALES:  # de más alto a más bajo
        if medir(y_v, p_val, u)["recall"] >= OBJETIVO_RECALL:
            elegido = u
            break
    if elegido is None:
        elegido = min(UMBRALES)
        print(f"\n[AVISO] Ningún umbral detecta el {OBJETIVO_RECALL:.0%} de los ataques reservados; se usa el más bajo.")
    print(f"\n[*] Umbral elegido con la validación: {elegido}")

    # 2) Modelo final con todo KDDTrain+ y medición única en KDDTest+
    print("\n[*] Entrenando el modelo final con todo KDDTrain+ (otro minuto)...")
    modelo = crear_modelo()
    modelo.fit(X_train, a_binario(etq_train))
    p_test = probabilidad_ataque(modelo, X_test)
    mostrar("PRUEBA OFICIAL KDDTest+ (informativa: NO se usó para elegir el umbral)", y_test, p_test)

    for u in (0.5, elegido):
        m = medir(y_test, p_test, u)
        tn, fp, fn, tp = m["matriz"]
        print(f"\nUmbral {u} en KDDTest+: normales bien {tn}, falsas alarmas {fp}, ataques no detectados {fn}, ataques detectados {tp}")