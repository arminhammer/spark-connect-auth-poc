package com.yourco.spark.auth

import com.github.benmanes.caffeine.cache.{Cache, Caffeine, Expiry}
import org.apache.hadoop.conf.Configuration
import org.apache.spark.internal.Logging
import software.amazon.awssdk.auth.credentials.{
  AwsBasicCredentials,
  AwsCredentials,
  AwsCredentialsProvider
}
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

/** AWS S3A CredentialsProvider that resolves per-user credentials by exchanging
  * the JWT carried in the current execution context.
  *
  * ┌───────────────────────────────────────────────────────────────────────────┐
  * │ Security model │ │ │ │ A Spark Connect server hosts ONE SparkContext
  * shared by all sessions. │ │ Writing credentials to sc.hadoopConfiguration
  * (the naive approach) is │ │ therefore a multi-tenant security bug: the last
  * writer wins, leaking │ │ credentials across concurrent or sequential │
  * Instead, this provider resolves credentials on-demand per-call by reading │
  * │ the JWT from `this.conf` — the Hadoop Configuration injected by S3A at │ │
  * construction time. The JWT flows here via: │ │ session.conf.set(JWT_KEY,
  * jwt) ← per-session SQLConf (driver) │ │ → SessionState.newHadoopConf() ←
  * overlays ALL sqlConf keys verbatim │ │ → HadoopFsRelation.broadcastedConf ←
  * broadcast to executors │ │ → S3AFileSystem.initialize(conf) →
  * JwtAWSCredentialsProvider(conf) │ │ SQLConf is per-session, so `this.conf`
  * is tenant-isolated. │ │ Credentials are NEVER stored in
  * sc.hadoopConfiguration. │
  * └───────────────────────────────────────────────────────────────────────────┘
  *
  * S3A instantiates this class via reflection. The (Configuration) constructor
  * is the preferred form for Hadoop 3.x ReflectionUtils.
  */
class JwtAWSCredentialsProvider(conf: Configuration)
    extends AwsCredentialsProvider
    with Logging {

  override def resolveCredentials(): AwsCredentials = {
    val jwt = findJwt()
    val creds = JwtAWSCredentialsProvider.cache.get(
      jwt,
      _ => {
        logInfo(
          s"[JwtAWSCredentialsProvider] Cache miss — exchanging JWT for credentials " +
            s"(jwt prefix=${jwt.take(8)}...)"
        )
        AuthServiceClient.exchangeJwtForSts(jwt)
      }
    )
    logDebug(
      s"[JwtAWSCredentialsProvider] Resolved credentials: " +
        s"accessKeyId prefix=${creds.accessKeyId.take(8)}..."
    )
    AwsBasicCredentials.create(creds.accessKeyId, creds.secretAccessKey)
  }

  /** Read the JWT from `this.conf`.
    *
    * `this.conf` is the Hadoop Configuration captured at S3A initialisation
    * time (passed by S3A's ReflectionUtils to our constructor). It was produced
    * by SessionState.newHadoopConf(), which overlays all per-session SQLConf
    * entries verbatim — including `spark.connect.auth.jwt` set by
    * CredentialInjectionRule. That Configuration is then broadcast to executors
    * as part of the query plan, so this single read path works on the driver,
    * on executor task threads, AND on S3A's internal async CompletableFuture
    * thread pool.
    */
  private def findJwt(): String =
    Option(conf.get(JwtAWSCredentialsProvider.JWT_KEY))
      .filter(_.nonEmpty)
      .getOrElse(
        throw new IllegalStateException(
          s"[JwtAWSCredentialsProvider] JWT not found under conf key " +
            s"'${JwtAWSCredentialsProvider.JWT_KEY}'. " +
            s"Ensure CredentialInjectionRule has fired for this session."
        )
      )
}

object JwtAWSCredentialsProvider {

  /** Key written to per-session SQLConf by CredentialInjectionRule:
    * session.conf.set(JWT_KEY, jwt) From there it flows automatically into
    * every Hadoop Configuration produced by SessionState.newHadoopConf() —
    * including the broadcast Configuration received by
    * JwtAWSCredentialsProvider(conf) on both driver and executors.
    */
  val JWT_KEY = "spark.connect.auth.jwt"

  /** How many seconds before JWT expiry to evict the credential cache entry.
    * This ensures we never hand out credentials whose JWT is about to be
    * rejected by the auth service on the next renewal.
    */
  private val EXPIRY_BUFFER_SECONDS = 60L

  /** Caffeine cache: JWT string → StsCredentials.
    *
    * Each entry lives until EXPIRY_BUFFER_SECONDS before the JWT's own `exp`
    * claim, so credentials are always refreshed before they could be rejected.
    *
    * If the JWT has no `exp` claim (shouldn't happen in production) or is
    * already within the buffer window, the entry is given a 0-nanosecond TTL
    * and Caffeine evicts it immediately — forcing a fresh auth-service call on
    * the next S3A operation.
    *
    * The cache is JVM-global and keyed by the raw JWT string. Different users
    * have cryptographically distinct JWTs so they always get distinct entries.
    * This is safe across sessions: cache reads are purely functional (JWT in,
    * credentials out) with no shared mutable state per entry.
    */
  private[auth] val cache: Cache[String, StsCredentials] =
    Caffeine
      .newBuilder()
      .expireAfter(new Expiry[String, StsCredentials] {

        /** TTL in nanoseconds from the moment the entry is first created. */
        override def expireAfterCreate(
            jwt: String,
            creds: StsCredentials,
            currentTimeNanos: Long
        ): Long = ttlNanos(jwt)

        /** On cache hit we don't extend the TTL — keep the original expiry. */
        override def expireAfterUpdate(
            jwt: String,
            creds: StsCredentials,
            currentTimeNanos: Long,
            currentDurationNanos: Long
        ): Long = currentDurationNanos

        override def expireAfterRead(
            jwt: String,
            creds: StsCredentials,
            currentTimeNanos: Long,
            currentDurationNanos: Long
        ): Long = currentDurationNanos
      })
      .build[String, StsCredentials]()

  /** Compute the cache TTL in nanoseconds from now.
    *
    * Parses the `exp` claim from the JWT payload (base64url-decoded JSON) using
    * only the JDK and returns: max(0, exp_epoch_seconds - now_epoch_seconds -
    * EXPIRY_BUFFER_SECONDS) converted to nanoseconds.
    *
    * Returns 0 (immediate eviction) if the JWT has no `exp` or is already
    * within the buffer window — forcing a fresh call on the next S3A operation.
    */
  private def ttlNanos(jwt: String): Long = {
    try {
      // A JWT is three base64url segments separated by '.'.  The payload is
      // the second segment.  We only need the `exp` numeric field.
      val payload = jwt.split("\\.")(1)
      // base64url → base64 (pad to multiple of 4 with '=')
      val padded = payload + "=" * ((4 - payload.length % 4) % 4)
      val json =
        new String(Base64.getUrlDecoder.decode(padded), StandardCharsets.UTF_8)

      // Extract `exp` without pulling in a JSON library.
      // Matches:  "exp":1234567890  (integer, no spaces assumed — true of all
      // standard JWT libraries; add a more robust parser if needed).
      val expRegex = """"exp"\s*:\s*(\d+)""".r
      expRegex.findFirstMatchIn(json).map(_.group(1).toLong) match {
        case Some(expEpochSec) =>
          val nowSec = Instant.now().getEpochSecond
          val ttlSec = expEpochSec - nowSec - EXPIRY_BUFFER_SECONDS
          val ttlClamped = math.max(0L, ttlSec)
          TimeUnit.SECONDS.toNanos(ttlClamped)
        case None =>
          // No `exp` claim — expire immediately to force re-fetch.
          0L
      }
    } catch {
      case e: Exception =>
        // Malformed JWT — expire immediately; the auth service will reject it.
        0L
    }
  }
}
