package com.yourco.spark.auth

// Spark 4.x: gRPC is shaded inside spark-connect under
// org.sparkproject.connect.grpc.* — NOT the upstream io.grpc.* package.
import org.sparkproject.connect.grpc.{
  Context,
  Contexts,
  Metadata,
  ServerCall,
  ServerCallHandler,
  ServerInterceptor,
  Status
}
import org.apache.spark.internal.Logging

class JwtExtractInterceptor extends ServerInterceptor with Logging {

  override def interceptCall[ReqT, RespT](
      call: ServerCall[ReqT, RespT],
      headers: Metadata,
      next: ServerCallHandler[ReqT, RespT]
  ): ServerCall.Listener[ReqT] = {
    val method = call.getMethodDescriptor.getFullMethodName
    logDebug(s"[JwtExtractInterceptor] interceptCall: method=$method")

    val rawHeader = Option(
      headers.get(
        Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)
      )
    )

    JwtAuth.extractBearer(method, rawHeader).flatMap { token =>
      JwtAuth.validateToken(method, token).toOption
    } match {
      case None =>
        logWarning(
          s"[JwtExtractInterceptor] Rejecting call — missing or invalid token: method=$method"
        )
        call.close(
          Status.UNAUTHENTICATED.withDescription("Valid Bearer token required"),
          new Metadata()
        )
        new ServerCall.Listener[ReqT] {} // no-op: discard further messages

      case Some(token) =>
        logDebug(
          s"[JwtExtractInterceptor] Token valid — wrapping call with JWT listener: method=$method"
        )
        val ctx =
          Context.current().withValue(JwtExtractInterceptor.JWT_KEY, token)
        val delegate = Contexts.interceptCall(ctx, call, headers, next)
        new ServerCall.Listener[ReqT] {
          private def withJwt[A](f: => A): A = {
            JwtAuth.CURRENT_JWT.set(token)
            try f
            finally JwtAuth.CURRENT_JWT.remove()
          }
          override def onMessage(message: ReqT): Unit = withJwt(
            delegate.onMessage(message)
          )
          override def onHalfClose(): Unit = withJwt(delegate.onHalfClose())
          override def onCancel(): Unit = withJwt(delegate.onCancel())
          override def onComplete(): Unit = withJwt(delegate.onComplete())
          override def onReady(): Unit = withJwt(delegate.onReady())
        }
    }
  }
}

object JwtExtractInterceptor {
  val JWT_KEY: Context.Key[String] = Context.key("jwt-token")
}
