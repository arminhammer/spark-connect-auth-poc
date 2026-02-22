package com.yourco.spark.auth

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.SparkSessionExtensions
import org.apache.spark.sql.catalyst.plans.logical.LogicalPlan
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.internal.Logging
import java.util.concurrent.atomic.AtomicBoolean

class CredentialInjectionExtension
    extends (SparkSessionExtensions => Unit)
    with Logging {
  override def apply(extensions: SparkSessionExtensions): Unit = {
    logInfo(
      "[CredentialInjectionExtension] Registering CredentialInjectionRule as a resolution rule"
    )
    extensions.injectResolutionRule { session =>
      logDebug(
        s"[CredentialInjectionExtension] Creating CredentialInjectionRule for new session instance=${System.identityHashCode(session)}"
      )
      new CredentialInjectionRule(session)
    }
  }
}

class CredentialInjectionRule(session: SparkSession) extends Rule[LogicalPlan] {
  // One rule instance per session (injectResolutionRule contract).
  // hadoopConfInitialized guards the one-time write of non-credential S3A
  // settings (endpoint, path style, provider class) to sc.hadoopConfiguration.
  // Credentials are NEVER written there — see JwtAWSCredentialsProvider.
  private val hadoopConfInitialized = new AtomicBoolean(false)
  private val sessionId = System.identityHashCode(session).toString

  override def apply(plan: LogicalPlan): LogicalPlan = {
    logDebug(
      s"[CredentialInjectionRule] apply called for session=$sessionId, " +
        s"plan=${plan.getClass.getSimpleName}"
    )

    val jwt = JwtAuth.CURRENT_JWT.get()

    if (jwt != null && jwt.nonEmpty) {
      // -----------------------------------------------------------------------
      // 1. Write the JWT into per-session SQLConf.
      //
      //    session.conf is per-session (not shared across tenants).
      //    SessionState.newHadoopConf() overlays ALL sqlConf entries verbatim
      //    into each task's Hadoop Configuration, so the JWT arrives in the
      //    `conf` parameter of JwtAWSCredentialsProvider on every thread —
      //    including S3A's internal async CompletableFuture thread pool.
      //
      //    Called on EVERY plan: each query may run on a different
      //    ExecutionThread from the pool and must re-populate the conf each time.
      // -----------------------------------------------------------------------
      session.conf.set(JwtAWSCredentialsProvider.JWT_KEY, jwt)
      logDebug(
        s"[CredentialInjectionRule] JWT written to session.conf for " +
          s"session=$sessionId (jwt prefix=${jwt.take(8)}...)"
      )

      // -----------------------------------------------------------------------
      // 2. One-time per-session: push non-credential S3A config into
      //    sc.hadoopConfiguration so it flows through newHadoopConf() into
      //    executor task configurations.
      //
      //    Why sc.hadoopConfiguration?  SessionState.newHadoopConf() overlays
      //    sqlConf.getAllConfs() verbatim (key "spark.hadoop.fs.s3a.endpoint",
      //    not "fs.s3a.endpoint"), so session.conf.set("spark.hadoop.*") never
      //    reaches S3A.  Writing the stripped key to sc.hadoopConfiguration is
      //    the only supported way to apply dynamic runtime config.
      //
      //    These values are non-sensitive and identical across all sessions, so
      //    writing to the shared sc.hadoopConfiguration is safe.
      // -----------------------------------------------------------------------
      if (hadoopConfInitialized.compareAndSet(false, true)) {
        val hadoopConf = session.sparkContext.hadoopConfiguration

        // Sync non-credential spark.hadoop.* keys (endpoint, path style, etc.)
        session.conf.getAll
          .filter { case (k, _) =>
            k.startsWith("spark.hadoop.") && !isCredentialKey(k)
          }
          .foreach { case (k, v) =>
            val hk = k.stripPrefix("spark.hadoop.")
            logDebug(
              s"[CredentialInjectionRule] Syncing $hk=$v to hadoopConf for session=$sessionId"
            )
            hadoopConf.set(hk, v)
          }

        // Register the per-execution credentials provider.
        // JwtAWSCredentialsProvider resolves credentials lazily at the point
        // of each S3A call using the JWT from the task's Hadoop Configuration.
        // Credentials are NEVER stored in the shared sc.hadoopConfiguration.
        hadoopConf.set(
          "fs.s3a.aws.credentials.provider",
          classOf[JwtAWSCredentialsProvider].getName
        )

        // SECURITY: Disable the static Hadoop FileSystem cache for S3A.
        //
        // S3A FileSystem instances are cached in a JVM-global URI → FileSystem
        // map.  A cached instance retains its construction-time `conf` (which
        // contains the JWT that was current when it was first created).  If
        // the cache were enabled, a second user hitting the same URI would get
        // the first user's FileSystem — and therefore the first user's JWT and
        // credentials.
        //
        // With the cache disabled, every FileSystem.get() call creates a fresh
        // S3AFileSystem initialised with the current task's per-session conf,
        // ensuring complete tenant isolation.
        //
        // This is also set at server startup via --conf, but we enforce it here
        // in code so isolation is guaranteed even if the startup flag is dropped.
        hadoopConf.set("fs.s3a.impl.disable.cache", "true")
        logInfo(
          s"[CredentialInjectionRule] S3A config initialised for session=$sessionId — " +
            s"provider=${classOf[JwtAWSCredentialsProvider].getName}"
        )
      }

    } else {
      // No JWT on this thread.  Unset the session.conf key so that a reused
      // session on a different ExecutionThread cannot carry a stale JWT.
      try { session.conf.unset(JwtAWSCredentialsProvider.JWT_KEY) } catch { case _: Exception => () }
      logDebug(
        s"[CredentialInjectionRule] No JWT in CURRENT_JWT for session=$sessionId — " +
          s"JWT cleared from session.conf"
      )
    }

    plan // pass-through — we never modify the query plan
  }

  /** Returns true for spark.hadoop.* keys that carry credential material. These
    * must NEVER be written to sc.hadoopConfiguration (shared mutable global) —
    * they are resolved per-call by JwtAWSCredentialsProvider.
    */
  private def isCredentialKey(k: String): Boolean = {
    val lower = k.toLowerCase
    lower.contains(".access.key") ||
    lower.contains(".secret.key") ||
    lower.contains(".session.token") ||
    lower.contains(".credentials.provider")
  }
}
