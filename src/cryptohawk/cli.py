from __future__ import annotations

import argparse
import json
import logging
import os
import socket

from alembic import command
from alembic.config import Config

from cryptohawk.api.app import app
from cryptohawk.cbom.exporter import CycloneDXExporter
from cryptohawk.config import settings
from cryptohawk.risk.engine import RiskEngine
from cryptohawk.scanners.source import SourceScanner
from cryptohawk.scanners.tls import TLSScanner
from cryptohawk.services.executor import AssetScanExecutor
from cryptohawk.services.scheduler import ScanScheduler, SchedulerConfig
from cryptohawk.services.worker import ScanWorker, WorkerConfig
from cryptohawk.storage.continuous import ContinuousRepository
from cryptohawk.storage.database import FindingRepository
from cryptohawk.storage.inventory import InventoryRepository
from cryptohawk.storage.queue import ScanQueueRepository
from cryptohawk.storage.quotas import QuotaRepository


def _print(findings) -> None:
    print(json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2))


def _default_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def _migration_config() -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


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

    worker = sub.add_parser("worker", help="Run a durable CryptoHawk scan worker")
    worker.add_argument("--worker-id", default=_default_worker_id())
    worker.add_argument("--lease-seconds", type=int, default=60)
    worker.add_argument("--poll-interval", type=float, default=1.0)
    worker.add_argument("--retry-backoff", type=int, default=5)
    worker.add_argument("--scan-timeout", type=float, default=5.0)
    worker.add_argument("--once", action="store_true")

    scheduler = sub.add_parser("scheduler", help="Enqueue due continuous scan schedules")
    scheduler.add_argument("--poll-interval", type=float, default=5.0)
    scheduler.add_argument("--batch-size", type=int, default=100)
    scheduler.add_argument("--once", action="store_true")

    migrate = sub.add_parser("migrate", help="Manage the CryptoHawk database schema")
    migrate.add_argument("action", choices=("upgrade", "downgrade", "current"))
    migrate.add_argument("revision", nargs="?")

    args = parser.parse_args()
    if args.command == "migrate":
        config = _migration_config()
        if args.action == "upgrade":
            command.upgrade(config, args.revision or "head")
        elif args.action == "downgrade":
            command.downgrade(config, args.revision or "-1")
        else:
            command.current(config, verbose=True)
        return

    repo = FindingRepository(settings.database_url)
    if settings.auto_create_schema:
        repo.create_schema()
    engine = RiskEngine()

    if args.command == "scan-source":
        findings = [engine.assess(obs) for obs in SourceScanner().scan_path(args.path)]
        if not args.no_persist:
            repo.upsert_many(findings)
        _print(findings)
    elif args.command == "scan-tls":
        scanner = TLSScanner(allow_private_targets=settings.allow_private_targets)
        findings = [engine.assess(obs) for obs in scanner.scan(args.hostname, args.port)]
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
    elif args.command in {"worker", "scheduler"}:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        inventory = InventoryRepository(settings.database_url)
        quota = QuotaRepository(inventory)
        queue = ScanQueueRepository(inventory, quota)
        continuous = ContinuousRepository(inventory)
        if settings.auto_create_schema:
            quota.create_schema()
            queue.create_schema()
            continuous.create_schema()
        executor = AssetScanExecutor(
            risk_engine=engine,
            source_scanner=SourceScanner(),
            tls_scanner=TLSScanner(allow_private_targets=settings.allow_private_targets),
        )
        if args.command == "worker":
            runner = ScanWorker(
                inventory,
                repo,
                queue,
                executor=executor,
                config=WorkerConfig(
                    worker_id=args.worker_id,
                    lease_seconds=args.lease_seconds,
                    poll_interval=args.poll_interval,
                    retry_backoff_seconds=args.retry_backoff,
                    scan_timeout=args.scan_timeout,
                ),
                history=continuous,
            )
            if args.once:
                runner.run_once()
            else:
                runner.run_forever()
        else:
            runner = ScanScheduler(
                inventory,
                queue,
                continuous,
                executor=executor,
                config=SchedulerConfig(
                    poll_interval=args.poll_interval,
                    batch_size=args.batch_size,
                ),
            )
            if args.once:
                runner.run_once()
            else:
                runner.run_forever()
