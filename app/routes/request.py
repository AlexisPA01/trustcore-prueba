from typing import Optional, List
from fastapi.responses import JSONResponse

from fastapi import APIRouter, Query, Body
import requests
from app.database import db

router = APIRouter()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

@router.get(
        "/v1/vulnerabilities",
        tags=["Vulnerabilities"],
        summary="Obtener vulnerabilidades",
        description="Consulta vulnerabilidades desde la API usando filtros opcionales.",
        responses={
            200: {
                "description": "Vulnerabilidades obtenidas correctamente",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Vulnerabilidades obtenidas correctamente",
                            "total": 2000,
                            "vulnerabilities": []
                        }
                    }
                }
            },
            422: {
                "description": "Error en los parametros"
            },
            500: {
                "description": "Error consultando la API",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Error obteniendo vulnerabilidades",
                            "error": "Detalle del error",
                            "total": 0,
                            "vulnerabilities": []
                        }
                    }
                }
            }
        })
def get_vulnerabilities(
    cpeName: Optional[str] = Query(
        None,
        description="El parametro cpeName es una cadena de caracteres compuesta por 13 valores separados por dos puntos que describen un producto",
        openapi_examples={
            "Ejemplo": {"value": "cpe:2.3:o:microsoft:windows_10:1607:-:-:-:-:-:-:-"}
        }),
    cveId: Optional[str] = Query(
        None,
        description="El parametro cveId es un identificador único de Vulnerabilidades y Exposiciones",
        openapi_examples={
            "Ejemplo": {"value": "CVE-2019-1010218"}
        }),
    cveIds: Optional[str] = Query(
        None,
        description="El parametro cveIds es una cadena de caracteres compuesta por identificadores únicoc de Vulnerabilidades y Exposiciones",
        openapi_examples={
            "Ejemplo": {"value": "CVE-2019-1010218,CVE-2019-1010"}
        }),
    vulnStatuses: Optional[str] = Query(
        None,
        description="El parametro vulnStatuses es una cadena de texto que describe un estado, soporta multiples estados seperados por coma",
        openapi_examples={
            "Ejemplo": {"value": "Modified,Analyzed"}
        }),
    cveTag: Optional[str] = Query(
        None,
        description="El parametro cveTag es una cadena de texto que asignado a un tag",
        openapi_examples={
            "Ejemplo": {"value": "disputed"}
        }),
    cvssV2Metrics: Optional[str] = Query(
        None,
        description="El parametro cvssV2Metrics es una cadena de texto que describe las metricas, no soporta consultas con el parametro 'cvssV3Metrics' y 'cvssv4Metrics'",
        openapi_examples={
            "Ejemplo": {"value": "AV:N/AC:H/Au:N/C:C/I:C/A:C"}
        }),
    cvssV2Severity: Optional[str] = Query(
        None,
        description="El parametro cvssV2Severity es una cadena de texto que describe la gravedad respecto a la forma de calificar 'CVSSv2', no soporta consultas con el parametro 'cvssV3Severity' y 'cvssv4Severity'",
        openapi_examples={
            "Ejemplo": {"value": "LOW"}
        }),
    cvssV3Metrics: Optional[str] = Query(
        None,
        description="El parametro cvssV3Metrics es una cadena de texto que describe el vector 'CVSSv3' de metricas, no soporta consultas con el parametro 'cvssV3Metrics' y 'cvssv4Metrics'",
        openapi_examples={
            "Ejemplo": {"value": "AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L"}
        }),
    cvssV3Severity: Optional[str] = Query(
        None,
        description="El parametro cvssV3Severity es una cadena de texto que describe la gravedad respecto a la forma de calificar 'CVSSv3', no soporta consultas con el parametro 'cvssV2Severity' y 'cvssv4Severity'",
        openapi_examples={
            "Ejemplo": {"value": "CRITICAL"}
        }),
    cvssV4Metrics: Optional[str] = Query(
        None,
        description="El parametro cvssV4Metrics es una cadena de texto que describe el vector 'CVSSv4' de metricas, no soporta consultas con el parametro 'cvssV2Metrics' y 'cvssv3Metrics'",
        openapi_examples={
            "Ejemplo": {"value": "AV:A/AC:H/PR:H/UI:N"}
        }),
    cvssV4Severity: Optional[str] = Query(
        None,
        description="El parametro cvssV4Severity es una cadena de texto que describe la gravedad respecto a la forma de calificar 'CVSSv4', no soporta consultas con el parametro 'cvssV2Severity' y 'cvssv3Severity'",
        openapi_examples={
            "Ejemplo": {"value": "HIGH"}
        }),
    cweId: Optional[str] = Query(
        None,
        description="El parametro cweId es una cadena de texto que siga la guia de las enumeraciones de debilidades comunes (CWE-ID)",
        openapi_examples={
            "Ejemplo": {"value": "CWE-287"}
        }),
    hasCertAlerts: Optional[bool] = Query(
        None,
        description="El parametro hasCertAlerts es un booleano que permite la busqueda para aquellas vulnerabilidade que tengan alertas tecnicas de (US-CERT)"
        ),
    hasCertNotes: Optional[bool] = Query(
        None,
        description="El parametro hasCertNotes es un booleano que permite la busqueda para aquellas vulnerabilidade que tenga una nota de vulnerabilidad de (CERT/CC)"
        ),
    hasKev:Optional[bool] = Query(
        None,
        description="El parametro hasKev es un booleano que permite la busqueda para aquellas vulnerabilidades que aparescan en (CISA's KEV)"
        ),
    hasOval:Optional[bool] = Query(
        None,
        description="El parametro hasOval es un booleano que permite la busqueda para aquellas vulnerabilidade que contengan información de (MITRE's OVAL)"
        ),
    isVulnerable: Optional[bool] = Query(
        None,
        description="El parametro isVulnerable es un booleano que permite la busqueda para aquellas vulnerabilidades asociadas con un especifico CVE, si se busca con 'isVulnerable', 'cpeName' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "cpeName=cpe:2.3:o:microsoft:windows_10:1607&isVulnerable"}
        }),
    kevStartDate: Optional[str] = Query(
        None,
        description="El parametro kevStartDate es una fecha que busca los registros que fueron añadidos en el catalogo KEV durrante un periodo especifico, si se busca con 'kevStartDate', 'kevEndDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "kevStartDate=2023-01-01T00:00:00.000Z&kevEndDate=2023-04-30T23:59:59.000Z"}
        }),
    kevEndDate: Optional[str] = Query(
        None,
        description="El parametro kevEndDate es una fecha que busca los registros que fueron añadidos en el catalogo KEV durrante un periodo especifico, si se busca con 'kevEndDate', 'kevStartDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "kevStartDate=2023-01-01T00:00:00.000Z&kevEndDate=2023-04-30T23:59:59.000Z"}
        }),
    keywordExactMatch: Optional[bool] = Query(
        None,
        description="El parametro keywordExactMatch es una booleano que permite la busqueda mediante una palabra o frase en la posición actual, si se busca con 'keywordExactMatch', 'keywordSearch' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "keywordSearch=Microsoft Outlook&keywordExactMatch"}
        }),
    keywordSearch: Optional[str] = Query(
        None,
        description="El parametro keywordSearch es una cadena de texto que busca en la descripción actual",
        openapi_examples={
            "Ejemplo": {"value": "Microsoft"}
        }),
    lastModStartDate: Optional[str] = Query(
        None,
        description="El parametro lastModStartDate es una fecha que busca los registros que fueron modificados en un periodo especifico, si se busca con 'lastModStartDate', 'lastModEndDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00"}
        }),
    lastModEndDate: Optional[str] = Query(
        None,
        description="El parametro lastModStartDate es una fecha que busca los registros que fueron modificados en un periodo especifico, si se busca con 'lastModEndDate', 'lastModStartDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00"}
        }),
    noRejected: Optional[bool] = Query(
        None,
        description="El parametro noRejected es un booleano que permite la busqueda para aquellas vulnerabilidade con el estado rechazadas"
        ),
    pubStartDate: Optional[str] = Query(
        None,
        description="El parametro lastModStartDate es una fecha que busca los registros que fueron añadidos por el NVD en un periodo especifico, si se busca con 'pubStartDate', 'pubEndDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "pubStartDate=2021-08-04T00:00:00.000&pubEndDate=2021-10-22T00:00:00.000"}
        }),
    pubEndDate: Optional[str] = Query(
        None,
        description="El parametro lastModStartDate es una fecha que busca los registros que fueron añadidos por el NVD en un periodo especifico, si se busca con 'pubEndDate', 'pubStartDate' es requerido",
        openapi_examples={
            "Ejemplo": {"value": "pubStartDate=2021-08-04T00:00:00.000&pubEndDate=2021-10-22T00:00:00.000"}
        }),
    resultsPerPage: Optional[int] = Query(
        2000,
        description="El parametro resultsPerPage es el número maximo de registros que va a devolver la busqueda en un sola respuesta de la API, el valor por defecto y maximo es 2000",
        openapi_examples={
            "Ejemplo": {"value": 2000}
        }),
    startIndex: Optional[int] = Query(
        None,
        description="El parametro startIndex espeficica el indice del primer registro devuelvo, el indice empieza desde 0",
        openapi_examples={
            "Ejemplo": {"value": "0"}
        }),
    sourceIdentifier: Optional[str] = Query(
        None,
        description="El parametro sourceIdentifier es una cadena de texto que representa el valor exacto de las fuentes de los datos en los registros",
        openapi_examples={
            "Ejemplo": {"value": "cve@mitre.org"}
        }),
    versionEnd: Optional[str] = Query(
        None,
        description="El parametro versionEnd tiene que ser combinado con versionEndType y devuelve los registros en rangos de versiones especificas, si se usa tiene que incluirse de manera obligatoria el parametro 'virtualMatchString'",
        openapi_examples={
            "Ejemplo": {"value": "virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.6&versionStartType=including&versionEnd=2.7&versionEndType=excluding"}
        }),
    versionEndType: Optional[str] = Query(
        None,
        description="El parametro versionEndType tiene que ser combinado con versionEnd y devuelve los registros en rangos de versiones especificas, si se usa tiene que incluirse de manera obligatoria el parametro 'virtualMatchString'",
        openapi_examples={
            "Ejemplo": {"value": "virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.6&versionStartType=including&versionEnd=2.7&versionEndType=excluding"}
        }),
    versionStart: Optional[str] = Query(
        None,
        description="El parametro versionStart tiene que ser combinado con versionStartType y devuelve los registros en rangos de versiones especificas, si se usa tiene que incluirse de manera obligatoria el parametro 'virtualMatchString'",
        openapi_examples={
            "Ejemplo": {"value": "virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.2&versionStartType=including&versionEnd=2.6&versionEndType=excluding"}
        }),
    versionStartType: Optional[str] = Query(
        None,
        description="El parametro versionStartType tiene que ser combinado con versionStart y devuelve los registros en rangos de versiones especificas, si se usa tiene que incluirse de manera obligatoria el parametro 'virtualMatchString'",
        openapi_examples={
            "Ejemplo": {"value": "virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.2&versionStartType=including&versionEnd=2.6&versionEndType=excluding"}
        }),
    virtualMatchString: Optional[str] = Query(
        None,
        description="El parametro virtualMatchString filtra de forma más amplia",
        openapi_examples={
            "Ejemplo": {"value": "cpe:2.3:*:*:*:*:*:*:de"}
        })
):
    
    params = {}

    if cpeName:
        params["cpeName"] = cpeName

    if cveId:
        params["cveId"] = cveId

    if cveIds:
        params["cveIds"] = cveIds

    if vulnStatuses:
        params["vulnStatuses"] = vulnStatuses

    if cveTag:
        params["cveTag"] = cveTag

    if cvssV2Metrics and not cvssV3Metrics and not cvssV4Metrics:
        params["cvssV2Metrics"] = cvssV2Metrics

    if cvssV2Severity and not cvssV3Severity and not cvssV4Severity:
        params["cvssV2Severity"] = cvssV2Severity

    if cvssV3Metrics and not cvssV2Metrics and not cvssV4Metrics:
        params["cvssV3Metrics"] = cvssV3Metrics

    if cvssV3Severity and not cvssV2Severity and not cvssV4Severity:
        params["cvssV3Severity"] = cvssV3Severity

    if cvssV4Metrics and not cvssV2Metrics and not cvssV3Metrics:
        params["cvssV4Metrics"] = cvssV4Metrics

    if cvssV4Severity and not cvssV2Severity and not cvssV3Severity:
        params["cvssV4Severity"] = cvssV4Severity

    if cweId:
        params["cweId"] = cweId

    if hasCertAlerts:
        params["hasCertAlerts"] = hasCertAlerts

    if hasCertNotes:
        params["hasCertNotes"] = hasCertNotes

    if hasKev:
        params["hasKev"] = hasKev

    if hasOval:
        params["hasOval"] = hasOval

    if isVulnerable and cpeName:
        params["isVulnerable"] = isVulnerable

    if kevStartDate and kevEndDate:
        params["kevStartDate"] = kevStartDate

    if kevEndDate and kevStartDate:
        params["kevEndDate"] = kevEndDate

    if keywordExactMatch and keywordSearch:
        params["keywordExactMatch"] = keywordExactMatch

    if keywordSearch:
        params["keywordSearch"] = keywordSearch

    if lastModStartDate and lastModEndDate:
        params["lastModStartDate"] = lastModStartDate

    if lastModEndDate and lastModStartDate:
        params["lastModEndDate"] = lastModEndDate

    if noRejected:
        params["noRejected"] = noRejected

    if pubStartDate and pubEndDate:
        params["pubStartDate"] = pubStartDate

    if pubEndDate and pubStartDate:
        params["pubEndDate"] = pubEndDate

    if resultsPerPage:
        params["resultsPerPage"] = resultsPerPage

    if startIndex:
        params["startIndex"] = startIndex

    if sourceIdentifier:
        params["sourceIdentifier"] = sourceIdentifier

    if versionEnd and versionEndType and virtualMatchString:
        params["versionEnd"] = versionEnd

    if versionEndType and versionEnd and virtualMatchString:
        params["versionEndType"] = versionEndType

    if versionStart and versionStartType and virtualMatchString:
        params["versionStart"] = versionStart

    if versionStartType and versionStart and virtualMatchString:
        params["versionStartType"] = versionStartType

    if virtualMatchString and not cpeName:
        params["virtualMatchString"] = virtualMatchString

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()

        return {
            "message": "Vulnerabilidades obtenidas correctamente",
            "total": len(data.get("vulnerabilities")),
            "vulnerabilities": data.get("vulnerabilities")
        }

    except Exception as e:
        return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Error obteniendo vulnerabilidades",
            "error": str(e),
            "total": 0,
            "vulnerabilities": []
        })

@router.post(
        "/v1/fixed",
        tags=["Vulnerabilities"],
        summary="Registrar vulnerabilidades",
        description="Registra una o varias vulnerabilidades 'fixeadas'(por cve_id) y las guarda en la base de datos para excluirla de los registros activos",
        responses={
            200: {
                "description": "Vulnerabilidades registradas correctamente",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Vulnerabilidades registradas correctamente",
                            "total": 2,
                            "inserted_ids": [
                                "CVE-1999-0082",
                                "CVE-1999-1471"
                            ]
                        }
                    }
                }
            },
            422: {
                "description": "Error de validación"
            },
            500: {
                "description": "Error registrando registros en la base de datos",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Error registrando vulnerabilidades",
                            "error": "Detalle del error",
                            "total": 0,
                            "inserted_ids": []
                        }
                    }
                }
            }
        })
def create_vulnerabilities(
    vulnerabilities: List[dict] = Body (
        examples=[
            [
                {
                    "cve": {
                        "id": "CVE-1999-0082",
                        "sourceIdentifier": "cve@mitre.org",
                        "vulnStatus": "Modified"
                    }
                },
                {
                    "cve": {
                        "id": "CVE-1999-1471",
                        "sourceIdentifier": "cve@mitre.org",
                        "vulnStatus": "Modified"
                    }
                }
            ]
        ])
    ):

    try:
        result = db.vulnerabilities.insert_many(vulnerabilities)

        return {
            "message": "Vulnerabilidades registradas correctamente",
            "total": len(result.inserted_ids),
            "inserted_ids": [id["cve"]["id"] for id in vulnerabilities]
        }
    except Exception as e:
        return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Error registrando vulnerabilidades",
            "error": str(e),
            "total": 0,
            "inserted_ids": []
        })

@router.get(
        "/v1/vulnerabilities/active",
        tags=["Vulnerabilities"],
        summary="Obtener vulnerabilidades activas",
        description="Consulta vulnerabilidades desde la API excluyendo aquellas que esten 'fixeadas'",
        responses={
            200: {
                "description": "Vulnerabilidades activas consultadas correctamente",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Vulnerabilidades actvivas consultandas correctamente",
                            "total": 2,
                            "inserted_ids": [
                                "CVE-1999-0082",
                                "CVE-1999-1471"
                            ]
                        }
                    }
                }
            },
            500: {
                "description": "Error consultando registros en la base de datos o en la API",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Error obteniendo vulnerabilidades activas",
                            "error": "Detalle del error",
                            "total": 0,
                            "inserted_ids": []
                        }
                    }
                }
            }
        })
def get_vulnerabilities_active():
    try:
        response = requests.get(BASE_URL, params={}, timeout=10)

        response.raise_for_status()

        data = response.json()

        fixed_cves = {
            vulnerability["cve"]["id"]
            for vulnerability in db.vulnerabilities.find()
        }

        filtered_vulnerabilities = [
            vulnerability
            for vulnerability in data.get("vulnerabilities")
            if vulnerability["cve"]["id"] not in fixed_cves
        ]

        data["vulnerabilities"] = filtered_vulnerabilities

        return {
                "message": "Vulnerabilidades actvivas consultandas correctamente",
                "total": len(filtered_vulnerabilities),
                "vulnerabilities": data.get("vulnerabilities")
            }
    except Exception as e:
        print(e)
        return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Error obteniendo vulnerabilidades activas",
            "error": str(e),
            "total": 0,
            "vulnerabilities": []
        })

@router.get(
        "/v1/vulnerabilities/summary",
        tags=["Vulnerabilities"],
        summary="Obtener resumen de las vulnerabilidades",
        description="Consulta el resumen de las vulberabilidades haciendo un conteo de los tipos de severidades que hay.",
        responses={
            200: {
                "description": "Resumen obetnido correctamente",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Resumen de vulnerabilidades calculado correctamente",
                            "total": 2000,
                            "summary": {
                                "severities": {
                                    "CRITICAL": 7,
                                    "HIGH": 1020,
                                    "MEDIUM": 752,
                                    "LOW": 221
                                }
                            }
                        }
                    }
                }
            },
            500: {
                "description": "Error consultando los registros en la API para hacer el resumen",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Error calculando el resumen de las vulnerabilidadess",
                            "error": "Detalle del error",
                            "total": 0
                        }
                    }
                }
            }
        })
def get_summary_vulnerabilities():
    severity = {
        'severities': {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
    }

    total = 0

    try:
        response = requests.get(BASE_URL, params={}, timeout=10)

        response.raise_for_status()

        data = response.json()

        for vulnerability in data["vulnerabilities"]:
            metrics = vulnerability["cve"]["metrics"]

            if metrics.get("cvssMetricV2"):
                for metricV2 in metrics.get("cvssMetricV2"):
                    severity["severities"][metricV2.get("baseSeverity")] += 1
                    total += 1

            if metrics.get("cvssMetricV30"):
                for metricV30 in metrics.get("cvssMetricV30"):
                    severity["severities"][metricV30.get("cvssData").get("baseSeverity")] += 1
                    total += 1

            if metrics.get("cvssMetricV31"):
                for metricV31 in metrics.get("cvssMetricV31"):
                    severity["severities"][metricV31.get("cvssData").get("baseSeverity")] += 1
                    total += 1

            if metrics.get("cvssMetricV40"):
                for metricV4 in metrics.get("cvssMetricV40"):
                    severity["severities"][metricV4.get("baseSeverity")] += 1
                    total += 1

        return {
                "message": "Resumen de vulnerabilidades calculado correctamente",
                "total": total,
                "summary": severity
            }
    except Exception as e:
        return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Error calculando el resumen de las vulnerabilidades",
            "error": str(e)
        })
    
@router.delete(
        "/v1/unfixed",
        tags=["Vulnerabilities"],
        summary="Eliminar vulnerabilidades",
        description="Eliminar una o varias vulnerabilidades 'fixeadas'(por cve_id) de la base de datos",
        responses={
            200: {
                "description": "Vulnerabilidades eliminadas correctamente",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Vulnerabilidades eliminadas correctamente",
                            "total": 2,
                            "deleted_ids": [
                                "CVE-1999-0082",
                                "CVE-1999-1471"
                            ]
                        }
                    }
                }
            },
            422: {
                "description": "Error de validación"
            },
            500: {
                "description": "Error eliminando registros en la base de datos",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "Error eliminando vulnerabilidades",
                            "error": "Detalle del error",
                            "total": 0,
                            "inserted_ids": []
                        }
                    }
                }
            }
        })
def delete_vulnerabilities(
    vulnerabilities: List[dict] = Body (
        examples=[
            [
                {
                    "cve": {
                        "id": "CVE-1999-0082",
                        "sourceIdentifier": "cve@mitre.org",
                        "vulnStatus": "Modified"
                    }
                },
                {
                    "cve": {
                        "id": "CVE-1999-1471",
                        "sourceIdentifier": "cve@mitre.org",
                        "vulnStatus": "Modified"
                    }
                }
            ]
        ])
    ):

    try:
        cve_ids = [item["cve"]["id"] for item in vulnerabilities]

        filtro = {"cve.id": {"$in": cve_ids}}

        result = db.vulnerabilities.delete_many(filtro)

        return {
            "message": "Vulnerabilidades eliminadas correctamente",
            "total": result.deleted_count,
            "deleted_ids": [item["cve"]["id"] for item in vulnerabilities]
        }
    except Exception as e:
        return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Error eliminando vulnerabilidades",
            "error": str(e),
            "total": 0,
            "deleted_ids": []
        })