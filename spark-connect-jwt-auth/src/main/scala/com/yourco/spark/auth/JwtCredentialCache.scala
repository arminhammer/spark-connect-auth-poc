package com.yourco.spark.auth

import com.github.benmanes.caffeine.cache.{Cache, Caffeine, Expiry}
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

/** Shared constants and Caffeine credential cache used by both the Spark 3 and
  * Spark 4 variants of JwtAWSCredentialsProvider.
  *
  * Named separately from JwtAWSCredentialsProvider to avoid the Scala compiler
  * requirement that a class and its companion object reside in the same file —
  * the JwtAWSCredentialsProvider class is in a version-specific source
  * directory (scala-spark-3/ or scala-spark-4/) while this object lives in the
  * shared src/main/scala/ tree.
  */
object JwtCredentialCache {

  /** Written to per-session SQLConf by CredentialInjectionRule.
    *
    * The "spark.hadoop." prefix is load-bearing across both Spark versions:
    *
    * Spark 4.0 — newHadoopConf() copies ALL SQLConf keys verbatim, so the JWT
    * arrives in the task Configuration as JWT_KEY itself. The Spark-4 class
    * reads conf.get(JWT_KEY).
    *
    * Spark 3.5 — newHadoopConf() ONLY copies spark.hadoop.* keys and strips the
    * prefix, so the JWT arrives as JWT_CONF_KEY ("connect.auth.jwt"). The
    * Spark-3 class reads conf.get(JWT_CONF_KEY).
    *
    * The isCredentialKey filter in CredentialInjectionRule prevents this key
    * from ever being written to sc.hadoopConfiguration (the JVM-global shared
    * state shared across all sessions).
    */
  val JWT_KEY = "spark.hadoop.connect.auth.jwt"

  /** Hadoop Configuration key used inside Spark 3.5 tasks. Spark 3.5's
    * newHadoopConf() strips the "spark.hadoop." prefix from JWT_KEY when
    * writing it into the task Configuration.
    */
  val JWT_CONF_KEY: String = JWT_KEY.stripPrefix("spark.hadoop.")

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
  private[auth] def ttlNanos(jwt: String): Long = {
    try {
      // A JWT is three base64url segments separated by '.'.  The payload is
      // the second segment.  We only need the `exp` numeric field.
      val payload = jwt.split("\\.")(1)
      // base64url → base64 (pad to multiple of 4 with '=')
      val padded = payload + "=" * ((4 - payload.length % 4) % 4)
      val json =
        new String(Base64.getUrlDecoder.decode(padded), StandardCharsets.UTF_8)

      // Extract `exp` without pulling in a JSON library.
      val expRegex = """"exp"\s*:\s*(\d+)""".r
      expRegex.findFirstMatchIn(json).map(_.group(1).toLong) match {
        case Some(expEpochSec) =>
          val nowSec = Instant.now().getEpochSecond
          val ttlSec = expEpochSec - nowSec - EXPIRY_BUFFER_SECONDS
          TimeUnit.SECONDS.toNanos(math.max(0L, ttlSec))
        case None =>
          // No `exp` claim — expire immediately to force re-fetch.
          0L
      }
    } catch {
      case _: Exception =>
        // Malformed JWT — expire immediately; the auth service will reject it.
        0L
    }
  }
}
