# Failure Injection and Recovery Validation

CryptoHawk treats worker, collector-network, and database interruptions as expected operational faults. The CI failure-injection drill verifies that these faults do not leave durable scan state permanently running, burn incorrect retry attempts, or leak workspace scan capacity.

## CI scenarios

The `postgres-failure-injection` job runs against PostgreSQL 17 after applying the production Alembic migration chain.

### Worker process disappears while holding a lease

The drill claims a durable scan job, simulates the worker disappearing without completing or failing the job, advances beyond the lease expiry, and runs lease recovery. The job must return to `queued`, its workspace capacity slot must be released, and a replacement worker must reclaim it as the second attempt and complete it successfully.

### Worker disappears on the final allowed attempt

A job with one allowed attempt is abandoned until its lease expires. Recovery must mark it `failed` rather than requeueing it indefinitely, and the workspace capacity slot must be released.

### Collector/network interruption

A real `ScanWorker` runs an executor that raises an `OSError` on its first collection attempt and succeeds on the second. CryptoHawk must classify the interruption as retryable, return the job to `queued`, preserve attempt accounting, and complete the retry successfully.

### PostgreSQL interruption during an in-flight scan

The executor stops the actual PostgreSQL service container after the worker owns a durable lease. Persistence and retry bookkeeping cannot complete while the database is unavailable. PostgreSQL is then restarted, and the drill reuses the same SQLAlchemy engine so `pool_pre_ping` must discard stale connections and reconnect. After the abandoned lease expires, queue recovery must requeue the job, release the leaked capacity, and allow a replacement worker to complete the second attempt.

## Release invariants

The gate fails unless all scenarios demonstrate:

- durable jobs leave `running` after an expired lease;
- retry attempts are counted exactly once per actual claim;
- terminal failures do not retry forever;
- replacement workers can reclaim recoverable work;
- database restart recovery works through the existing repository engine;
- collector/network faults follow the worker's retry policy;
- workspace scan capacity returns to zero after recovery; and
- final quota reconciliation finds no leaked runtime capacity.

## Scope

This is a deterministic CI recovery gate, not a claim of exhaustive chaos engineering. It deliberately targets CryptoHawk's most important durability boundaries: queue leases, retry state, workspace concurrency accounting, transient collector failure handling, and PostgreSQL reconnection. Production pilots should additionally exercise infrastructure-specific failure modes such as node loss, network partitions, storage exhaustion, managed-database failover, and orchestrator rescheduling in their deployment environment.
