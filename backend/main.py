from fastapi import FastAPI

from app.services.vulnerability_parser import parse_vulnerability_report

app = FastAPI(

    title="DVCE",

    description="Dependency Vulnerability Contextual Exploitability Engine",

    version="0.1.0",

)


@app.get("/health")

def health_check():

    return {

        "status": "ok",

        "service": "DVCE",

        "message": "Backend is running"

    }


@app.post("/vulnerabilities/parse")

def parse_vulnerabilities(report: dict):

    vulnerabilities = parse_vulnerability_report(report)

    return {

        "project": report.get("project"),

        "total_vulnerabilities": len(vulnerabilities),

        "vulnerabilities": vulnerabilities

    }
 