from fastapi import APIRouter, HTTPException
import requests

router = APIRouter(prefix="/dni", tags=["DNI"])

@router.get("/{dni}")
def consultar_dni(dni: str):

    if len(dni) != 8 or not dni.isdigit():
        raise HTTPException(status_code=400, detail="DNI inválido")

    url = f"https://graphperu.daustinn.com/api/query/{dni}"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Referer": "https://graphperu.daustinn.com/"
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        data = response.json()
        print("DATA:", data)

        # 🔴 AHORA VALIDAMOS COMO OBJETO
        if not isinstance(data, dict) or "fullName" not in data:
            raise HTTPException(status_code=404, detail="DNI no encontrado")

        return {
            "dni": dni,
            "nombres": data.get("names", ""),
            "apellido_paterno": data.get("paternalLastName", ""),
            "apellido_materno": data.get("maternalLastName", ""),
            "nombre_completo": data.get("fullName", "")
        }

    except requests.RequestException as e:
        print("ERROR:", e)
        raise HTTPException(status_code=503, detail="Error consultando DNI")
