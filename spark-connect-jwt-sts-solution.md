# Spark Connect JWT → STS Multi-Tenant Credential Injection

## Architecture

```
PySpark Client                 Spark Connect Server (credentialless)
┌─────────────┐               ┌──────────────────────────────────────────────┐
│ token=<JWT> │──── gRPC ────▶│ 1. JwtExtractInterceptor: JWT → gRPC Context │
└─────────────┘               │ 2. CredentialInjectionRule: JWT → STS creds   │
                              │ 3. Sets fs.s3a.* on session hadoop config     │
                              │ 4. Plans query (driver lists files via STS)   │
                              │ 5. Serializes tasks WITH hadoop config        │
                              └──────────────┬──────────────┬────────────────┘
                                             │              │
                                        ┌────▼───┐    ┌────▼───┐
                                        │Executor│    │Executor│
                                        │reads   │    │reads   │
                                        │parquet │    │parquet │
                                        │via STS │    │via STS │
                                        └────────┘    └────────┘
```

The Spark Connect server starts with **no data lake credentials**. Each client session's JWT is exchanged for short-lived STS credentials, which are injected into that session's Hadoop config and automatically propagated to executor tasks through Spark's normal serialization.

---

## 1. Client (PySpark)

Nothing custom. The `token=` parameter is built into the Spark Connect connection string.

```python
from pyspark.sql import SparkSession

jwt = get_jwt_from_your_idp()  # e.g. Dex, Okta, your auth service

spark = SparkSession.builder \
    .remote(f"sc://spark-connect.internal:443/;token={jwt}") \
    .getOrCreate()

# Just use Spark normally — credentials are resolved server-side
df = spark.read.parquet("s3a://data-lake/tenant-a/events/")
df.groupBy("event_type").count().show()
```

---

## 2. gRPC Interceptor — Extract JWT into Context

This fires on every inbound gRPC call, before the session is resolved. It pulls the Bearer token and stashes it in the gRPC `Context` so downstream code can read it.

```scala
// src/main/scala/com/yourco/spark/auth/JwtExtractInterceptor.scala
package com.yourco.spark.auth

import io.grpc._

class JwtExtractInterceptor extends ServerInterceptor {

  override def interceptCall[ReqT, RespT](
      call: ServerCall[ReqT, RespT],
      headers: Metadata,
      next: ServerCallHandler[ReqT, RespT]
  ): ServerCall.Listener[ReqT] = {
    val token = Option(
      headers.get(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER))
    ).filter(_.startsWith("Bearer "))
     .map(_.stripPrefix("Bearer "))
     .getOrElse("")

    val ctx = Context.current().withValue(JwtExtractInterceptor.JWT_KEY, token)
    Contexts.interceptCall(ctx, call, headers, next)
  }
}

object JwtExtractInterceptor {
  val JWT_KEY: Context.Key[String] = Context.key("jwt-token")
}
```

---

## 3. SparkSessionExtensions — Inject STS Credentials Per Session

This is the core piece. A custom analyzer rule that fires during query planning. On first execution for a session, it reads the JWT from gRPC context, exchanges it for STS credentials via your auth service, and sets them on the session's Hadoop configuration.

Those credentials then propagate to executors automatically — Spark serializes the session's Hadoop config into every task.

```scala
// src/main/scala/com/yourco/spark/auth/CredentialInjectionExtension.scala
package com.yourco.spark.auth

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.SparkSessionExtensions
import org.apache.spark.sql.catalyst.plans.logical.LogicalPlan
import org.apache.spark.sql.catalyst.rules.Rule
import java.util.concurrent.ConcurrentHashMap

class CredentialInjectionExtension extends (SparkSessionExtensions => Unit) {
  override def apply(extensions: SparkSessionExtensions): Unit = {
    extensions.injectResolutionRule { session =>
      new CredentialInjectionRule(session)
    }
  }
}

class CredentialInjectionRule(session: SparkSession) extends Rule[LogicalPlan] {
  import CredentialInjectionRule._

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val sessionId = session.sessionUUID

    // Only inject once per session
    if (!injectedSessions.containsKey(sessionId)) {
      val jwt = JwtExtractInterceptor.JWT_KEY.get()

      if (jwt != null && jwt.nonEmpty) {
        // Exchange JWT for scoped STS credentials
        val creds = AuthServiceClient.exchangeJwtForSts(jwt)

        // Set on session's hadoop config — this is what gets
        // serialized into tasks and sent to executors
        session.conf.set("spark.hadoop.fs.s3a.access.key", creds.accessKeyId)
        session.conf.set("spark.hadoop.fs.s3a.secret.key", creds.secretAccessKey)
        session.conf.set("spark.hadoop.fs.s3a.session.token", creds.sessionToken)
        session.conf.set(
          "spark.hadoop.fs.s3a.aws.credentials.provider",
          "org.apache.hadoop.fs.s3a.TemporaryAWSCredentialsProvider"
        )

        injectedSessions.put(sessionId, true)
      }
    }

    plan // pass-through — we don't modify the query plan
  }
}

object CredentialInjectionRule {
  // Track which sessions already have credentials injected
  private val injectedSessions = new ConcurrentHashMap[String, Boolean]()
}
```

---

## 4. Auth Service Client — JWT → STS Exchange

This calls your auth service to exchange a user's JWT for scoped STS credentials. Your auth service is responsible for validating the JWT, determining what data the user can access, and calling AWS STS AssumeRole with the appropriate IAM role.

```scala
// src/main/scala/com/yourco/spark/auth/AuthServiceClient.scala
package com.yourco.spark.auth

import java.net.{HttpURLConnection, URL}
import scala.io.Source
import com.fasterxml.jackson.databind.ObjectMapper

case class StsCredentials(
  accessKeyId: String,
  secretAccessKey: String,
  sessionToken: String
)

object AuthServiceClient {
  private val mapper = new ObjectMapper()
  private val authServiceUrl = sys.env.getOrElse(
    "AUTH_SERVICE_URL", "http://auth-service.internal:8080"
  )

  /**
   * Exchange a JWT for short-lived STS credentials scoped to the user.
   *
   * Your auth service handles:
   *   1. Validate the JWT (sig, expiry, issuer, audience)
   *   2. Determine user identity and data access scope
   *   3. Call STS AssumeRole with an IAM role/policy scoped to the user
   *   4. Return the temporary credentials
   */
  def exchangeJwtForSts(jwt: String): StsCredentials = {
    val url = new URL(s"$authServiceUrl/v1/credentials/sts")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Authorization", s"Bearer $jwt")
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(5000)

    try {
      if (conn.getResponseCode != 200) {
        throw new SecurityException(
          s"Auth service returned ${conn.getResponseCode}"
        )
      }
      val body = Source.fromInputStream(conn.getInputStream).mkString
      val json = mapper.readTree(body)

      StsCredentials(
        accessKeyId = json.get("accessKeyId").asText(),
        secretAccessKey = json.get("secretAccessKey").asText(),
        sessionToken = json.get("sessionToken").asText()
      )
    } finally {
      conn.disconnect()
    }
  }
}
```

---

## 5. Server Startup Configuration

```bash
./sbin/start-connect-server.sh \
  --packages org.apache.spark:spark-connect_2.12:3.5.3,org.apache.hadoop:hadoop-aws:3.3.4 \
  --jars /opt/spark/plugins/jwt-credential-injection.jar \
  \
  # Register the gRPC interceptor and session extension
  --conf spark.connect.grpc.interceptor.classes=com.yourco.spark.auth.JwtExtractInterceptor \
  --conf spark.sql.extensions=com.yourco.spark.auth.CredentialInjectionExtension \
  \
  # CRITICAL: Disable filesystem cache to prevent cross-session credential leakage
  --conf spark.hadoop.fs.s3a.impl.disable.cache=true \
  \
  # No S3 credentials here — they come per-session from the auth service
  --conf spark.hadoop.fs.s3a.path.style.access=true
```

---

## 6. Build File

```xml
<!-- pom.xml -->
<project>
  <groupId>com.yourco</groupId>
  <artifactId>spark-connect-jwt-auth</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <!-- Provided by Spark at runtime -->
    <dependency>
      <groupId>org.apache.spark</groupId>
      <artifactId>spark-connect_2.12</artifactId>
      <version>3.5.3</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.apache.spark</groupId>
      <artifactId>spark-sql_2.12</artifactId>
      <version>3.5.3</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>io.grpc</groupId>
      <artifactId>grpc-api</artifactId>
      <version>1.56.1</version>
      <scope>provided</scope>
    </dependency>

    <!-- Shaded into the JAR -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
    </dependency>
  </dependencies>
</project>
```

---

## How Credentials Flow from Driver to Executors

This is the key thing to understand — **you don't need to do anything special for executors**.

```
Session A sets:
  spark.hadoop.fs.s3a.access.key = ASIA...USERA
  spark.hadoop.fs.s3a.session.token = FwoGZX...

Session B sets:
  spark.hadoop.fs.s3a.access.key = ASIA...USERB
  spark.hadoop.fs.s3a.session.token = FwoGZX...
```

When Session A runs `spark.read.parquet("s3a://bucket/data")`:

1. **Driver** resolves the query plan using Session A's Hadoop config (lists files via STS creds A)
2. **Driver** creates tasks. Each task carries a `SerializableConfiguration` — a serialized copy of the Hadoop Configuration from Session A, including the STS creds
3. **Executors** deserialize the task, call `FileSystem.get(uri, hadoopConf)`, which uses `TemporaryAWSCredentialsProvider` to read `access.key`, `secret.key`, `session.token` from the config
4. Executors read their assigned parquet shards using **User A's STS credentials**

Session B's tasks carry Session B's credentials. They never mix, as long as `fs.s3a.impl.disable.cache=true` is set.

---

## Critical: FileSystem Cache Isolation

Without `fs.s3a.impl.disable.cache=true`, Hadoop caches `FileSystem` instances by URI scheme + authority. This means:

- Session A accesses `s3a://bucket/` → creates `FileSystem` with creds A, caches it
- Session B accesses `s3a://bucket/` → **gets cached instance with creds A**

This is a credential leakage bug. Setting `fs.s3a.impl.disable.cache=true` forces a new `FileSystem` per task. There is a performance cost (no connection reuse across tasks), but it is the only safe option for multi-tenant credential isolation.

---

## Auth Service Contract

Your auth service needs one endpoint. Everything else is standard infrastructure.

```
POST /v1/credentials/sts
Authorization: Bearer <jwt>

Response 200:
{
  "accessKeyId": "ASIA...",
  "secretAccessKey": "...",
  "sessionToken": "FwoGZX...",
  "expiration": "2026-02-21T15:00:00Z"
}
```

Internally, this endpoint:
1. Validates the JWT (signature via JWKS from your IdP, expiry, issuer, audience)
2. Maps the JWT subject/claims to an IAM role ARN (e.g. `arn:aws:iam::role/tenant-a-data-reader`)
3. Calls `sts:AssumeRole` with an optional inline policy to further scope down permissions
4. Returns the temporary credentials

---

## What You Build vs. What's Off-the-Shelf

| Component | Custom? | Lines of code |
|-----------|---------|---------------|
| PySpark client `token=` | No — built into Spark Connect | 0 |
| `JwtExtractInterceptor` | Yes | ~25 |
| `CredentialInjectionExtension` + `Rule` | Yes | ~50 |
| `AuthServiceClient` | Yes | ~40 |
| Auth service (`JWT → STS`) | Yes | Varies (this is your real backend) |
| Server startup config | Config only | 5 lines of `--conf` |
| Spark Connect server | No — stock Apache Spark | 0 |
| Executor credential handling | No — stock Hadoop S3A | 0 |

Total custom Spark plugin code: **~115 lines of Scala in one JAR**.

---

## STS Token Expiry

STS tokens default to 1 hour. For most interactive queries this is fine. Options for long-running jobs:

- Set `DurationSeconds` up to 12h when calling AssumeRole (requires IAM role config)
- For queries exceeding the TTL, the `TemporaryAWSCredentialsProvider` does not refresh. You would need a custom `AwsCredentialsProvider` that calls back to the auth service — but this is an edge case for most Spark Connect workloads
