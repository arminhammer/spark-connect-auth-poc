package com.yourco.spark.auth

import org.apache.hadoop.conf.Configuration
import org.apache.spark.internal.Logging
import software.amazon.awssdk.auth.credentials.{
  AwsBasicCredentials,
  AwsCredentials,
  AwsCredentialsProvider
}

/** Spark 4 / Hadoop 3.4 variant — implements AWS SDK v2 AwsCredentialsProvider.
  *
  * JWT transport path in Spark 4: CredentialInjectionRule writes JWT_KEY to
  * session.conf (per-session SQLConf) → SessionState.newHadoopConf() copies ALL
  * SQLConf keys verbatim into the task Hadoop Configuration (no prefix
  * filtering) → S3AFileSystem.initialize(conf) →
  * JwtAWSCredentialsProvider(conf) → conf.get(JWT_KEY) returns the JWT directly
  *
  * S3A instantiates this class via reflection. The (Configuration) constructor
  * is the preferred form for Hadoop 3.x ReflectionUtils.
  */
class JwtAWSCredentialsProvider(conf: Configuration)
    extends AwsCredentialsProvider
    with Logging {

  override def resolveCredentials(): AwsCredentials = {
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
    AwsBasicCredentials.create(creds.accessKeyId, creds.secretAccessKey)
  }

  /** Spark 4: newHadoopConf() copies ALL SQLConf keys verbatim, so the JWT
    * arrives in this.conf under JWT_KEY ("spark.hadoop.connect.auth.jwt").
    */
  private def findJwt(): String =
    Option(conf.get(JwtCredentialCache.JWT_KEY))
      .filter(_.nonEmpty)
      .getOrElse(
        throw new IllegalStateException(
          s"[JwtAWSCredentialsProvider] JWT not found under conf key " +
            s"'${JwtCredentialCache.JWT_KEY}'. " +
            s"Ensure CredentialInjectionRule has fired for this session."
        )
      )
}
