package com.yourco.spark.auth

import com.amazonaws.auth.{
  AWSCredentials,
  AWSCredentialsProvider,
  BasicAWSCredentials,
  BasicSessionCredentials
}
import org.apache.hadoop.conf.Configuration
import org.apache.spark.internal.Logging

/** Spark 3.5 / Hadoop 3.3 variant — implements AWS SDK v1
  * AWSCredentialsProvider.
  *
  * JWT transport path in Spark 3.5: CredentialInjectionRule writes JWT_KEY
  * ("spark.hadoop.connect.auth.jwt") to session.conf (per-session SQLConf) →
  * SessionState.newHadoopConf() ONLY copies spark.hadoop.* keys and strips the
  * prefix, so the JWT arrives in the task Hadoop Configuration as JWT_CONF_KEY
  * ("connect.auth.jwt") → S3AFileSystem.initialize(conf) →
  * JwtAWSCredentialsProvider(conf) → conf.get(JWT_CONF_KEY) returns the JWT
  *
  * S3A (Hadoop 3.3.x) instantiates this class via reflection, trying
  * constructors in order: (URI, Configuration) → (Configuration) → (). The
  * (Configuration) form is used here.
  */
class JwtAWSCredentialsProvider(conf: Configuration)
    extends AWSCredentialsProvider
    with Logging {

  override def getCredentials(): AWSCredentials = {
    val jwt = findJwt()
    val creds = JwtCredentialCache.cache.get(
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
    if (creds.sessionToken.nonEmpty)
      new BasicSessionCredentials(
        creds.accessKeyId,
        creds.secretAccessKey,
        creds.sessionToken
      )
    else
      new BasicAWSCredentials(creds.accessKeyId, creds.secretAccessKey)
  }

  /** Required by the AWSCredentialsProvider interface. S3A calls this before
    * retrying a failed request; our cache handles refresh via TTL expiry so
    * there is nothing to do here.
    */
  override def refresh(): Unit = {}

  /** Spark 3.5: newHadoopConf() strips the "spark.hadoop." prefix when copying
    * SQLConf entries into the task Configuration, so the JWT arrives as
    * JWT_CONF_KEY ("connect.auth.jwt") — the bare key without the spark.hadoop.
    * prefix.
    */
  private def findJwt(): String =
    Option(conf.get(JwtCredentialCache.JWT_CONF_KEY))
      .filter(_.nonEmpty)
      .getOrElse(
        throw new IllegalStateException(
          s"[JwtAWSCredentialsProvider] JWT not found under conf key " +
            s"'${JwtCredentialCache.JWT_CONF_KEY}'. " +
            s"Ensure CredentialInjectionRule has fired for this session."
        )
      )
}
