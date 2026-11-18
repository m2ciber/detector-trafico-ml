# Detector de intrusiones de red con Machine Learning

Prototipo de sistema de detección de intrusiones (NIDS) en Python. Entrena un clasificador Random Forest con metadatos de flujos de red (duración, paquetes, bytes, puerto de destino y flags SYN) para distinguir tráfico normal de escaneos de puertos, fuerza bruta SSH y ataques DDoS.

## Problema que resuelve

Las reglas basadas solo en firmas fallan cuando un ataque varía su patrón. Este proyecto explora un enfoque complementario: aprender el comportamiento de cada tipo de tráfico a partir de sus estadísticas y generar alertas con un nivel de confianza.

## Cómo funciona

```text
[Datos de red] -> [pandas] -> [Entrenamiento Random Forest] -> [modelo .joblib] -> [Alertas]
```

1. `entrenar_modelo.py` genera un conjunto de datos **sintético** con cuatro clases (normal, port scan, fuerza bruta SSH, DDoS), entrena el modelo, muestra métricas y la importancia de cada característica, y guarda el modelo.
2. `detector_tiempo_real.py` carga el modelo y clasifica cinco flujos simulados, mostrando severidad y confianza.

## Evidencia de ejecución

![Ejecución del detector](captura.png)

## Cómo ejecutarlo (Windows)

```powershell
git clone https://github.com/m2ciber/detector-trafico-ml.git
cd detector-trafico-ml
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python entrenar_modelo.py
python detector_tiempo_real.py
```

## Limitaciones

- **Los datos son sintéticos.** Las cuatro clases están generadas con rangos muy distintos entre sí, por eso el modelo alcanza un 100 % de acierto. Ese resultado **no indica que funcione en una red real**: solo demuestra que el flujo de trabajo (datos, entrenamiento, evaluación, guardado y uso) es correcto.
- La "monitorización en tiempo real" es una simulación con cinco flujos escritos a mano. No captura tráfico real.
- No se ha evaluado con tráfico mezclado, ruido ni ataques que imiten al tráfico normal.

## Próximos pasos

- Entrenar con un conjunto de datos público (NSL-KDD o CIC-IDS2017) y comparar los resultados, que serán peores pero más realistas.
- Medir falsos positivos y falsos negativos por separado.
- Leer capturas reales de red (por ejemplo, archivos `.pcap`) en lugar de datos simulados.