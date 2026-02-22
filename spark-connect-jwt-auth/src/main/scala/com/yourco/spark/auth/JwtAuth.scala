package com.yourco.spark.auth

import org.apache.spark.internal.Logging
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.security.{KeyFactory, PublicKey, Signature}
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Shared JWT authentication helpers used by both the Spark-3 and Spark-4
  * flavours of JwtExtractInterceptor.
  *
  * The public key is loaded lazily on first use from the path given by the JVM
  * system property "spark.connect.auth.jwt.public.key.path", defaulting to
  * "jwt-public-key.pem" in the working directory.
  */
object JwtAuth extends Logging {

  private val PublicKeyPathProp = "spark.connect.auth.jwt.public.key.path"
  private val DefaultPublicKeyPath = "jwt-public-key.pem"

  /** Carries the validated JWT across thread boundaries.
    *
    * gRPC Context uses a plain ThreadLocal and does NOT propagate to child
    * threads.  Spark Connect creates a new ExecutionThread (via
    * `new ExecutionThread().start()`) from within a gRPC listener callback
    * that runs on the gRPC thread.  Because the ExecutionThread is a *child*
    * of the gRPC thread at creation time, InheritableThreadLocal values are
    * copied into it automatically by the JVM — giving CredentialInjectionRule
    * access to the JWT without any additional plumbing.
    */
  val CURRENT_JWT: InheritableThreadLocal[String] = new InheritableThreadLocal[String]

  /** Loaded once on first call to validateToken. */
  private lazy val publicKey: PublicKey = {
    val path = System.getProperty(PublicKeyPathProp, DefaultPublicKeyPath)
    logInfo(s"[JwtAuth] Loading JWT public key from: $path")
    val pem =
      new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8)
        .replaceAll("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s+", "")
    val keyBytes = Base64.getDecoder.decode(pem)
    val key = KeyFactory
      .getInstance("RSA")
      .generatePublic(new X509EncodedKeySpec(keyBytes))
    logInfo(s"[JwtAuth] Public key loaded successfully from: $path")
    key
  }

  /** Extract the Bearer token from the raw Authorization header value.
    *
    * Returns Some(token) on success, None if the header is absent or not a
    * Bearer scheme — in either case a debug message is logged.
    */
  def extractBearer(method: String, rawHeader: Option[String]): Option[String] =
    rawHeader match {
      case None =>
        logDebug(s"[JwtAuth] No Authorization header for method=$method")
        None
      case Some(v) if !v.startsWith("Bearer ") =>
        logDebug(
          s"[JwtAuth] Authorization header is not a Bearer token for method=$method"
        )
        None
      case Some(v) =>
        val token = v.stripPrefix("Bearer ")
        logDebug(
          s"[JwtAuth] Bearer token extracted for method=$method (prefix=${token.take(8)}...)"
        )
        Some(token)
    }

  /** Validate a JWT's RSA-SHA256 signature against the loaded public key.
    *
    * Returns Right(token) if the signature is valid, Left(reason) otherwise.
    * Expiry / claims validation is intentionally omitted here — in production
    * the auth service verifies those before issuing STS credentials.
    */
  def validateToken(method: String, token: String): Either[String, String] = {
    val parts = token.split("\\.")
    if (parts.length != 3) {
      val msg = s"JWT does not have 3 parts (got ${parts.length})"
      logWarning(s"[JwtAuth] $msg for method=$method")
      return Left(msg)
    }

    try {
      val message = s"${parts(0)}.${parts(1)}".getBytes(StandardCharsets.UTF_8)
      val sigBytes = Base64.getUrlDecoder.decode(parts(2))

      val sig = Signature.getInstance("SHA256withRSA")
      sig.initVerify(publicKey)
      sig.update(message)

      if (sig.verify(sigBytes)) {
        logDebug(
          s"[JwtAuth] JWT signature valid for method=$method (prefix=${token.take(8)}...)"
        )
        Right(token)
      } else {
        val msg = "JWT signature verification failed"
        logWarning(s"[JwtAuth] $msg for method=$method")
        Left(msg)
      }
    } catch {
      case e: Exception =>
        val msg = s"JWT validation error: ${e.getMessage}"
        logWarning(s"[JwtAuth] $msg for method=$method")
        Left(msg)
    }
  }
}
