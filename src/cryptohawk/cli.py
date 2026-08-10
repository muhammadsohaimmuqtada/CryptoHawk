from __future__ import annotations

import argparse
import json

from cryptohawk.api.app import app
from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.config import settings
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.storage.database import FindingRepository


def _print(findings) -> None:
    print(json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="cryptohawk")
    sub = parser.add_subparsers(dest="command", required=True)

    source = sub.add_parser("scan-source", help="Scan source tree for cryptographic assets")
    source.add_argument("path")
    source.add_argument("--no-persist", action="store_true")

    tls = sub.add_parser("scan-tls", help="Inspect TLS endpoint cryptography")
    tls.add_argument("hostname")
    tls.add_argument("--port", type=int, default=443)
    tls.add_argument("--no-persist", action="store_true")

    cbom = sub.add_parser("export-cbom", help="Export persistent inventory as CycloneDX 1.7 CBOM")
    cbom.add_argument("--output", default="cryptohawk-cbom.json")

    serve = sub.add_parser("serve", help="Run the CryptoHawk API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()
    repo = FindingRepository(settings.database_url)
    repo.create_schema()
    engine = RiskEngine()

    if args.command == "scan-source":
        findings = [engine.assess(obs) for obs in SourceScanner().scan_path(args.path)]
        if not args.no_persist:
            repo.upsert_many(findings)
        _print(findings)
    elif args.command == "scan-tls":
        findings = [engine.assess(obs) for obs in TLSScanner().scan(args.hostname, args.port)]
        if not args.no_persist:
            repo.upsert_many(findings)
        _print(findings)
    elif args.command == "export-cbom":
        document = CycloneDXExporter().export(repo.list_findings(limit=5000))
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
        print(args.output)
    elif args.command == "serve":
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
