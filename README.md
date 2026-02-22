# Spark Connect JWT Auth

A production-pattern Spark Connect plugin that implements **per-user JWT authentication** and **multi-tenant S3 credential injection** without ever writing credentials to the shared `SparkContext`.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Repository Layout](#repository-layout)
4. [Security Design](#security-design)
5. [Prerequisites](#prerequisites)
6. [Quick-Start: Running the End-to-End Test](#quick-start-running-the-end-to-end-test)
7. [Building the Plugin JAR](#building-the-plugin-jar)
8. [Starting the Spark Connect Server](#starting-the-spark-connect-server)
9. [Configuration Reference](#configuration-reference)
10. [Component Reference](#component-reference)
11. [Multi-tenancy & Threat Model](#multi-tenancy--threat-model)
12. [Production Hardening Notes](#production-hardening-notes)

---

## Overview

Spark Connect exposes a gRPC endpoint that multiple clients connect to simultaneously, each potentially belonging to a different user or tenant. Naively injecting per-user S3 credentials into `sc.hadoopConfiguration` is a **multi-tenant security bug** — that object is a JVM-global singleton shared by every session, so the last writer wins and credentials leak across users.

This project solves the problem end-to-end:

```
Client (Python)
  │  JWT in gRPC metadata header
  ▼
JwtExtractInterceptor (gRPC ServerInterceptor)
  │  validates RS256 signature, sets InheritableThreadLocal
  ▼
CredentialInjectionRule (Spark SQL resolution rule, runs per query)
  │  writes JWT into per-session SQLConf
  ▼
SessionState.newHadoopConf()  [Spark internal]
  │  overlays all SQLConf keys into the task's Hadoop Configuration
  ▼
JwtAWSCredentialsProvider (S3A AwsCredentialsProvider)
  │  reads JWT from this.conf, calls auth service, caches by JWT exp
  ▼
auth-service.py  →  returns user-scoped STS credentials
  ▼
S3A writes Parquet to s3proxy (or real AWS in production)
```

---

## Architecture

### Request flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Spark Connect server (single JVM)                                  │
│                                                                     │
│  gRPC thread pool                                                   │
│  ┌──────────────────────────────────────────────────┐              │
│  │ JwtExtractInterceptor                            │              │
│  │  • verifies RS256 signature (jwt-public-key.pem) │              │
│  │  • sets JwtAuth.CURRENT_JWT (InheritableThreadLocal)            │
│  │  • wraps each gRPC listener callback in try/finally remove()   │
│  └──────────────┬───────────────────────────────────┘              │
│                 │ ExecutionThread (child of gRPC thread)            │
│  ┌──────────────▼───────────────────────────────────┐              │
│  │ CredentialInjectionRule  (per-session instance)  │              │
│  │  • reads JWT from CURRENT_JWT                    │              │
│  │  • session.conf.set("spark.hadoop.connect.auth.jwt", …) │              │
│  │  • one-time: writes S3A config to sc.hadoopConf  │              │
│  │    (endpoint, path style — no secrets)           │              │
│  └──────────────┬───────────────────────────────────┘              │
│                 │                                                   │
│  ┌──────────────▼───────────────────────────────────┐              │
│  │ SessionState.newHadoopConf()  [Spark internal]   │              │
│  │  copies sc.hadoopConf + overlays ALL sqlConf keys│              │
│  │  → task Configuration contains the JWT           │              │
│  └──────────────┬───────────────────────────────────┘              │
│                 │ broadcast to executors                            │
│  ┌──────────────▼───────────────────────────────────┐              │
│  │ JwtAWSCredentialsProvider(conf)                  │              │
│  │  • conf.get("spark.hadoop.connect.auth.jwt") → JWT  │              │
│  │  • calls auth-service POST /v1/credentials/sts   │              │
│  │  • Caffeine cache: evicts at JWT exp - 60s       │              │
│  │  • returns AwsBasicCredentials per user          │              │
│  └──────────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### Key isolation guarantee

`session.conf` is backed by `SQLConf`, which is scoped to a single `SparkSession`. Spark Connect creates one `SparkSession` per client connection. `SessionState.newHadoopConf()` builds a **fresh** `Configuration` for every query, overlaying only *that session's* SQLConf. Different users' tasks therefore carry different JWTs in their `Configuration` objects — there is no shared mutable state carrying secrets.

---

## Repository Layout

```
spark-connect-auth/
├── create-jwt-token.py              # Generate RSA keypair + sample JWT
├── auth-service.py                  # Mock auth service (Flask): JWT → STS creds
├── pyspark-client.py                # End-to-end test client
├── docker-compose.s3proxy.yml       # Local S3-compatible storage (s3proxy)
├── log4j2.properties                # Spark server logging config
├── pyproject.toml                   # Python deps (uv / pip)
│
├── spark-connect-jwt-auth/          # Maven project — the Spark plugin
│   ├── pom.xml
│   └── src/main/scala/com/yourco/spark/auth/
│       ├── JwtAuth.scala                    # JWT validation + CURRENT_JWT ThreadLocal
│       ├── AuthServiceClient.scala          # HTTP client: JWT → StsCredentials
│       ├── CredentialInjectionExtension.scala  # SparkSessionExtensions entry point
│       │                                        # + CredentialInjectionRule
│       └── JwtCredentialCache.scala         # JWT_KEY constant + Caffeine cache
│                                            # (shared across Spark 3 and Spark 4)
│
│   └── src/main/scala-spark-4/com/yourco/spark/auth/
│       ├── JwtExtractInterceptor.scala      # gRPC interceptor (shaded grpc imports)
│       └── JwtAWSCredentialsProvider.scala  # S3A AwsCredentialsProvider (SDK v2)
│
│   └── src/main/scala-spark-3/com/yourco/spark/auth/
│       ├── JwtExtractInterceptor.scala      # gRPC interceptor (unshaded io.grpc.*)
│       └── JwtAWSCredentialsProvider.scala  # S3A AWSCredentialsProvider (SDK v1)
│
└── s3proxy/
    ├── Dockerfile
    └── entrypoint.sh
```

---

## Security Design

### The naive approach and why it fails

Writing credentials to `sc.hadoopConfiguration` in a resolution rule is the obvious first attempt:

```scala
// ❌ UNSAFE — sc.hadoopConfiguration is a JVM-global singleton
session.sparkContext.hadoopConfiguration.set("fs.s3a.access.key", creds.accessKeyId)
```

With concurrent sessions, the last `set()` call wins. UserA's tasks may silently execute using UserB's credentials with no error — a silent multi-tenant data exfiltration vulnerability.

### The correct approach: per-session SQLConf → per-task Hadoop Configuration

```scala
// ✅ SAFE — session.conf is per-SparkSession (per-client-connection)
session.conf.set("spark.hadoop.connect.auth.jwt", jwt)
```

`SessionState.newHadoopConf()` (bytecode-verified from `spark-sql_2.13-4.0.1.jar`) builds a fresh `Configuration` per query by:
1. Copying `sc.hadoopConfiguration` (shared base — no secrets)
2. Overlaying **all** `sqlConf.getAllConfs()` entries verbatim

The JWT therefore flows automatically into every task's `Configuration`, including S3A's internal async `CompletableFuture` thread pool — the only path that works on all threads.

### FileSystem cache isolation

Hadoop caches `FileSystem` instances in a JVM-global `URI → FileSystem` map. A cached `S3AFileSystem` would retain the `JwtAWSCredentialsProvider` instance from when it was first constructed — i.e. with the first user's `conf`. Subsequent users hitting the same URI would get the first user's provider.

`fs.s3a.impl.disable.cache=true` prevents this. It is enforced **in code** (`CredentialInjectionRule.hadoopConfInitialized` block) regardless of server startup flags:

```scala
hadoopConf.set("fs.s3a.impl.disable.cache", "true")
```

---

## Prerequisites

| Component | Version used |
|---|---|
| Java | OpenJDK 17 |
| Apache Spark | 4.0.1 (Scala 2.13) |
| Maven | 3.8.7 |
| Python | 3.12 |
| uv | 0.10.4 (or `pip`) |
| Docker | any recent version |

Python packages (from `pyproject.toml`):

```
cryptography>=46.0.5
flask>=3.1.0
pyjwt>=2.11.0
pyspark[connect]>=4.1.1
```

Install with:

```bash
uv sync
# or: pip install cryptography flask pyjwt "pyspark[connect]"
```

---

## Quick-Start: Running the End-to-End Test

Run each step in a separate terminal from the `/workspaces/spark-connect-auth` directory.

### Step 1 — Generate the RSA keypair (once only)

```bash
python create-jwt-token.py
```

Creates `jwt-private-key.pem` and `jwt-public-key.pem` in the working directory. These are used by the client to mint JWTs and by the server to validate them. Commit them (or mount them as secrets in production).

### Step 2 — Start s3proxy

```bash
docker compose -f docker-compose.s3proxy.yml up -d
```

Starts a local S3-compatible proxy on port `9090` backed by a Docker named volume (`s3data`). Credentials are `test-access-key-id` / `test-secret-access-key` (matching `auth-service.py`).

Create the test bucket directory inside the volume (one-time):

```bash
# Start an inspector container, create the directory, exit
docker compose -f docker-compose.s3proxy.yml run --rm inspector sh -c "mkdir -p /data/poc-data && ls /data"
```

To browse bucket contents later:

```bash
docker compose -f docker-compose.s3proxy.yml run --rm --profile inspect inspector
# then inside: find /data -type f
```

### Step 3 — Build the plugin JAR

```bash
cd spark-connect-jwt-auth
mvn package -Pspark-4 -q
cd ..
```

Output: `spark-connect-jwt-auth/target/spark-connect-jwt-auth-1.0.0-SNAPSHOT-spark-4-plugin.jar`

Symlink it onto Spark's system classpath so Hadoop's `Configuration.getClassByName()` can find it (required — `--jars` alone puts it on the wrong classloader for S3A's reflective instantiation):

```bash
ln -sf "$(pwd)/spark-connect-jwt-auth/target/spark-connect-jwt-auth-1.0.0-SNAPSHOT-spark-4-plugin.jar" \
       /opt/spark/jars/spark-connect-jwt-auth-plugin.jar
```

The symlink means a rebuild automatically takes effect on the next server start — no re-linking needed.

### Step 4 — Start the mock auth service

```bash
python auth-service.py
# Listens on http://localhost:8081
```

In production this is replaced by a real service that calls `sts:AssumeRole` and returns per-user temporary credentials. The interface is:

```
POST /v1/credentials/sts
Authorization: Bearer <jwt>

→ 200  {"accessKeyId": "...", "secretAccessKey": "...", "sessionToken": "..."}
→ 401  {"error": "..."}
```

### Step 5 — Start the Spark Connect server

```bash
/opt/spark/bin/spark-submit \
  --class org.apache.spark.sql.connect.service.SparkConnectServer \
  --master "local-cluster[2,1,1024]" \
  --conf spark.connect.grpc.interceptor.classes=com.yourco.spark.auth.JwtExtractInterceptor \
  --conf spark.sql.extensions=com.yourco.spark.auth.CredentialInjectionExtension \
  --conf "spark.driver.extraJavaOptions=\
    -Dlog4j2.configurationFile=file:///workspaces/spark-connect-auth/log4j2.properties \
    -Dspark.connect.auth.service.url=http://localhost:8081" \
  > /tmp/spark-server.log 2>&1 &
```

Wait until you see in the log:

```
INFO SparkConnectServer: Spark Connect server started at: 0:0:0:0:0:0:0:0:15002
```

```bash
grep "15002" /tmp/spark-server.log
```

> **Note:** `spark.hadoop.fs.s3a.impl.disable.cache=true` is no longer required on the command line — it is now enforced in `CredentialInjectionRule` to prevent accidental removal.

### Step 6 — Run the end-to-end test

```bash
python pyspark-client.py
```

Expected output:

```
JWT minted (prefix=eyJhbGciOiJSUzI1...)

Connecting to Spark Connect at sc://localhost:15002/ ...
Connected.

=== Hello World: sum of 1 to 10 ===
Sum of 1..10 = 55

=== Word count → Parquet → s3a://poc-data/word-count/ ===
+-------+-----+
|   word|count|
+-------+-----+
|connect|    1|
|  hello|    2|
|  spark|    2|
|  world|    1|
+-------+-----+

Writing Parquet to s3a://poc-data/word-count/ ...
Write complete.

Reading Parquet back from s3a://poc-data/word-count/ ...
...
Read-back verified.

All checks passed.
```

---

## Building the Plugin JAR

The Maven project has two profiles:

| Profile | Spark | Scala | gRPC imports |
|---|---|---|---|
| `spark-4` (default) | 4.0.1 | 2.13 | `org.sparkproject.connect.grpc.*` (shaded inside spark-connect JAR) |
| `spark-3` | 3.5.x | 2.12 | `io.grpc.*` (standard Maven Central) |

```bash
# Spark 4 (default)
cd spark-connect-jwt-auth && mvn package -Pspark-4

# Spark 3
cd spark-connect-jwt-auth && mvn package -Pspark-3
```

Caffeine 3.1.8 is shaded and relocated to `com.yourco.spark.auth.shaded.caffeine` to avoid classpath conflicts with any Caffeine version Spark might bundle in future.

---

## Starting the Spark Connect Server

Minimum required `--conf` flags:

| Flag | Value | Purpose |
|---|---|---|
| `spark.connect.grpc.interceptor.classes` | `com.yourco.spark.auth.JwtExtractInterceptor` | Registers the JWT-validating gRPC interceptor |
| `spark.sql.extensions` | `com.yourco.spark.auth.CredentialInjectionExtension` | Registers the SQL resolution rule |
| `spark.driver.extraJavaOptions` | `-Dspark.connect.auth.service.url=http://…` | Auth service URL (default: `http://localhost:8081`) |

Optional JVM system properties (set via `extraJavaOptions`):

| Property | Default | Purpose |
|---|---|---|
| `spark.connect.auth.service.url` | `http://localhost:8081` | Auth service endpoint (system property takes priority over `AUTH_SERVICE_URL` env var) |
| `spark.connect.auth.jwt.public.key.path` | `jwt-public-key.pem` | Path to the RSA public key used to validate incoming JWTs |

---

## Configuration Reference

### S3A settings (set by the client via `session.conf`)

These are written by the client and propagated server-side by `CredentialInjectionRule`:

| Key | Example value | Notes |
|---|---|---|
| `spark.hadoop.fs.s3a.endpoint` | `http://host.docker.internal:9090` | S3-compatible endpoint; use `host.docker.internal` from inside a devcontainer |
| `spark.hadoop.fs.s3a.path.style.access` | `true` | Required for s3proxy and most non-AWS endpoints |
| `spark.hadoop.fs.s3a.connection.ssl.enabled` | `false` | Disable TLS for local s3proxy |
| `spark.hadoop.fs.s3a.bucket.probe` | `0` | Skip bucket existence check on connect |
| `spark.hadoop.fs.s3a.multiobjectdelete.enable` | `false` | s3proxy does not implement the bulk `DeleteObjects` API; disabling this causes S3A to use single-object deletes |

### S3A settings written server-side by `CredentialInjectionRule`

These are written once per session to `sc.hadoopConfiguration` (non-credential, safe to share):

| Key | Value | Notes |
|---|---|---|
| `fs.s3a.aws.credentials.provider` | `com.yourco.spark.auth.JwtAWSCredentialsProvider` | Registered once; credentials resolved per-call from JWT |
| `fs.s3a.impl.disable.cache` | `true` | **Critical for multi-tenancy** — prevents cross-session FileSystem instance reuse |

---

## Component Reference

### `JwtExtractInterceptor` (gRPC `ServerInterceptor`)

Validates every inbound gRPC call:

1. Extracts the `Authorization: Bearer <token>` header from gRPC metadata.
2. Validates the RS256 signature against `jwt-public-key.pem`.
3. On success: wraps each `ServerCall.Listener` callback in a `try/finally` that sets and removes `JwtAuth.CURRENT_JWT` (an `InheritableThreadLocal`). The JWT is available to `CredentialInjectionRule` because Spark's `ExecutionThread` is spawned as a child of the gRPC callback thread and inherits the ThreadLocal value.
4. On failure: closes the call with `UNAUTHENTICATED`.

Two source variants exist:
- `scala-spark-4/` — uses `org.sparkproject.connect.grpc.*` (shaded gRPC in Spark 4)
- `scala-spark-3/` — uses `io.grpc.*` (unshaded gRPC in Spark 3)

### `JwtAuth`

Shared JWT utilities:
- `CURRENT_JWT: InheritableThreadLocal[String]` — carries the validated JWT from the gRPC interceptor into the query planner thread.
- `validateToken(method, token)` — RS256 signature verification using the JDK's `java.security.Signature` (no JWT library dependency on the server side).

### `CredentialInjectionExtension` / `CredentialInjectionRule`

Registered as a Catalyst **resolution rule** via `SparkSessionExtensions.injectResolutionRule`. One rule instance is created per `SparkSession` (per client connection).

On every query plan:
1. Reads the JWT from `JwtAuth.CURRENT_JWT`.
2. Writes it to `session.conf` (per-session, tenant-isolated).
3. One-time per session: syncs non-credential `spark.hadoop.*` keys from `session.conf` to `sc.hadoopConfiguration`, registers `JwtAWSCredentialsProvider`, and sets `fs.s3a.impl.disable.cache=true`.

### `AuthServiceClient`

Plain HTTP client that calls the auth service. URL resolved from (in priority order):
1. JVM system property `spark.connect.auth.service.url`
2. Environment variable `AUTH_SERVICE_URL`
3. Default `http://localhost:8081`

### `JwtCredentialCache` (shared constants and credential cache)

Lives in `src/main/scala/` alongside the other shared sources. Named separately from `JwtAWSCredentialsProvider` because Scala requires a class and its companion object to reside in the same file — here the class is in a version-specific directory while the shared state must live in the common tree.

Contains:
- `JWT_KEY = "spark.hadoop.connect.auth.jwt"` — written to `session.conf` by `CredentialInjectionRule`. The `spark.hadoop.` prefix is load-bearing: Spark 3.5's `newHadoopConf()` only copies `spark.hadoop.*` keys and strips the prefix (the JWT arrives as `connect.auth.jwt` in the task conf); Spark 4.0's `newHadoopConf()` copies all keys verbatim (the JWT arrives as `spark.hadoop.connect.auth.jwt`).
- `JWT_CONF_KEY = "connect.auth.jwt"` — the stripped form used by the Spark 3 class.
- The Caffeine cache (per-JWT TTL from `exp` claim, 60-second eviction buffer).

### `JwtAWSCredentialsProvider` (version-specific)

Two implementations in the version-specific source directories:

| Directory | Interface | AWS SDK |
|---|---|---|
| `scala-spark-4/` | `software.amazon.awssdk.auth.credentials.AwsCredentialsProvider` (`resolveCredentials()`) | SDK v2 |
| `scala-spark-3/` | `com.amazonaws.auth.AWSCredentialsProvider` (`getCredentials()` / `refresh()`) | SDK v1 |

Both variants:
1. Read the JWT from `this.conf` using the appropriate key (`JWT_KEY` in Spark 4, `JWT_CONF_KEY` in Spark 3).
2. Look up credentials in `JwtCredentialCache.cache` keyed by the raw JWT string.
3. On cache miss: call `AuthServiceClient.exchangeJwtForSts(jwt)` and cache the result.
4. Return `AwsBasicCredentials` / `BasicAWSCredentials`. The STS `sessionToken` field is intentionally not passed to the credential object in the PoC — s3proxy does not implement the `x-amz-security-token` header and returns 501 if it is included. When pointing at real AWS, switch to `AwsSessionCredentials` / `BasicSessionCredentials`.

---

## Multi-tenancy & Threat Model

| Component | Shared? | Tenant-isolated? | Mechanism |
|---|---|---|---|
| `session.conf` / `SQLConf` | No | ✅ Per `SparkSession` | JWT lives here; one session per client connection |
| `JwtAWSCredentialsProvider.this.conf` | No | ✅ Snapshot of session SQLConf at plan time | Per-task `Configuration` produced by `newHadoopConf()` |
| `S3AFileSystem` instances | Would be | ✅ Disabled by `impl.disable.cache=true` | Fresh instance per `FileSystem.get()` call — **critical load-bearing pin** |
| `JwtAWSCredentialsProvider.cache` | Yes (JVM-global) | ✅ Keyed by full JWT string | Different users have cryptographically distinct JWTs |
| `JwtAuth.CURRENT_JWT` | Thread-local | ✅ Cleared in `finally` every gRPC callback | Intermediate transport only; never outlives the callback |
| `sc.hadoopConfiguration` | Yes (JVM-global) | ✅ No secrets ever written | Only provider class name, endpoint, `disable.cache` |

---

## Production Hardening Notes

The following items are intentionally simplified for the PoC and should be addressed before production use:

1. **Real IdP** — Replace `jwt-public-key.pem` / `create-jwt-token.py` with a proper OIDC provider (Dex, Okta, Azure AD). Fetch the public key from the IdP's JWKS endpoint and rotate it automatically.

2. **Real auth service** — `auth-service.py` returns hard-coded credentials. Replace with a service that calls `sts:AssumeRole` with a role ARN scoped to the user's data access policy. When using real STS credentials, switch `JwtAWSCredentialsProvider` to return `AwsSessionCredentials` (SDK v2) / `BasicSessionCredentials` (SDK v1) instead of the basic form — s3proxy does not implement the `x-amz-security-token` header and returns 501 if the session token is sent.

3. **Multi-key JWT validation** — `JwtAuth.validateToken` loads a single public key. A production implementation should support a JWKS key set and rotate keys without a server restart.

4. **Credential cache eviction** — The Caffeine cache TTL is set to `JWT exp - 60s`. If the auth service issues STS credentials with a shorter lifetime than the JWT, align the cache TTL to `min(JWT exp, STS token exp) - buffer`.

5. **Auth service resilience** — `AuthServiceClient` has 5-second connect/read timeouts with no retry logic. Add exponential backoff and a circuit breaker for production.

6. **Executor-side auth service access** — `JwtAWSCredentialsProvider` calls the auth service from the driver. In `local-cluster` mode (used in this PoC) tasks run in separate JVMs on the same machine. In a real cluster the executors also call `resolveCredentials()`; ensure the auth service endpoint is reachable from executor nodes.

7. **Secret management** — `jwt-private-key.pem` is in the working directory. In production use a secrets manager (AWS Secrets Manager, Vault, Kubernetes Secret) and never commit private keys.
