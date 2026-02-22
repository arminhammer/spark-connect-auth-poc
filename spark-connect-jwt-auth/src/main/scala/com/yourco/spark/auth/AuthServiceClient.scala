package com.yourco.spark.auth

import java.net.{HttpURLConnection, URL}
import scala.io.Source
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.spark.internal.Logging

case class StsCredentials(
    accessKeyId: String,
    secretAccessKey: String,
    sessionToken: String
)

object AuthServiceClient extends Logging {
  private val mapper = new ObjectMapper()
  private val authServiceUrl = sys.props.getOrElse(
    "spark.connect.auth.service.url",
    sys.env.getOrElse("AUTH_SERVICE_URL", "http://localhost:8081")
  )

  logInfo(
    s"[AuthServiceClient] Initialized with authServiceUrl=$authServiceUrl"
  )

  /** Exchange a JWT for short-lived STS credentials scoped to the user.
    *
    * The auth service is responsible for:
    *   1. Validating the JWT (signature, expiry, issuer, audience)
    *   2. Determining user identity and data access scope
    *   3. Calling STS AssumeRole with the appropriate IAM role
    *   4. Returning the temporary credentials
    */
  def exchangeJwtForSts(jwt: String): StsCredentials = {
    val endpoint = s"$authServiceUrl/v1/credentials/sts"
    val jwtPreview = jwt.take(8) + "..."
    logDebug(
      s"[AuthServiceClient] exchangeJwtForSts: endpoint=$endpoint, jwt prefix=$jwtPreview"
    )

    val url = new URL(endpoint)
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Authorization", s"Bearer $jwt")
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(5000)
    logDebug(
      s"[AuthServiceClient] HTTP connection configured: method=POST, connectTimeout=5000ms, readTimeout=5000ms"
    )

    try {
      logDebug(s"[AuthServiceClient] Sending POST request to $endpoint")
      val responseCode = conn.getResponseCode
      logDebug(
        s"[AuthServiceClient] Response received: HTTP $responseCode from $endpoint"
      )

      if (responseCode != 200) {
        logWarning(
          s"[AuthServiceClient] Auth service returned non-200 status: HTTP $responseCode for jwt prefix=$jwtPreview"
        )
        throw new SecurityException(
          s"Auth service returned $responseCode"
        )
      }

      logDebug(s"[AuthServiceClient] Reading response body from $endpoint")
      val body = Source.fromInputStream(conn.getInputStream).mkString
      logDebug(s"[AuthServiceClient] Response body length=${body.length} chars")

      val json = mapper.readTree(body)
      logDebug(
        s"[AuthServiceClient] Parsed JSON response fields: ${json.fieldNames().hasNext}"
      )

      val creds = StsCredentials(
        accessKeyId = json.get("accessKeyId").asText(),
        secretAccessKey = json.get("secretAccessKey").asText(),
        sessionToken = json.get("sessionToken").asText()
      )

      logInfo(
        s"[AuthServiceClient] STS credentials parsed successfully (accessKeyId prefix=${creds.accessKeyId.take(8)}...)"
      )
      creds
    } finally {
      logDebug(
        s"[AuthServiceClient] Disconnecting HTTP connection to $endpoint"
      )
      conn.disconnect()
    }
  }
}
