// cert-validation-bypass.sc — Certificate validation bypass detection.
//
// Detects SSL_CTX_set_verify called with SSL_VERIFY_NONE, or custom verify
// callbacks that always return 1 (success), bypassing certificate validation.
//
// Output: JSON with findings array containing file, line, code, severity, and flow hops.

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  // Pattern 1: SSL_CTX_set_verify called with SSL_VERIFY_NONE (value 0).
  // SSL_CTX_set_verify(ctx, mode, verify_callback)
  // When mode == SSL_VERIFY_NONE (0x00), certificate verification is disabled.
  val verifyNoneCalls = cpg.call
    .nameExact("SSL_CTX_set_verify")
    .where(_.argument.argumentIndex(2).isLiteral.filter(_.code.matches("0|SSL_VERIFY_NONE")))

  // Also check SSL_set_verify (per-connection variant).
  val sslVerifyNoneCalls = cpg.call
    .nameExact("SSL_set_verify")
    .where(_.argument.argumentIndex(2).isLiteral.filter(_.code.matches("0|SSL_VERIFY_NONE")))

  val verifyNoneFindings = (verifyNoneCalls ++ sslVerifyNoneCalls).map { call =>
    s"""{
      "name": "cert-validation-bypass-verify-none",
      "file": "${escape(call.file.name.headOption.getOrElse("unknown"))}",
      "line": ${call.lineNumber.getOrElse(0)},
      "endLine": ${call.lineNumber.getOrElse(0)},
      "column": ${call.columnNumber.getOrElse(0)},
      "endColumn": ${call.columnNumber.getOrElse(0)},
      "code": "${escape(call.code)}",
      "severity": "critical",
      "flow": []
    }"""
  }

  // Pattern 2: Custom verify callbacks that always return 1.
  // Find functions used as the 3rd argument to SSL_CTX_set_verify
  // that unconditionally return 1 (literal) in all return paths.
  val callbackRefs = cpg.call
    .nameExact("SSL_CTX_set_verify")
    .argument
    .argumentIndex(3)
    .isIdentifier

  val callbackNames = callbackRefs.name.l.toSet

  // Also check function pointer references in SSL_set_verify.
  val sslCallbackRefs = cpg.call
    .nameExact("SSL_set_verify")
    .argument
    .argumentIndex(3)
    .isIdentifier

  val allCallbackNames = callbackNames ++ sslCallbackRefs.name.l.toSet

  // Find methods matching callback names where all return statements return 1.
  val alwaysReturnOneCallbacks = cpg.method
    .filter(m => allCallbackNames.contains(m.name))
    .filter { m =>
      val returns = m.ast.isReturn.l
      returns.nonEmpty && returns.forall { ret =>
        ret.astChildren.isLiteral.code.l.exists(c => c == "1" || c == "(1)")
      }
    }

  val callbackFindings = alwaysReturnOneCallbacks.map { method =>
    val callers = method.callIn.map { caller =>
      s"""{"file": "${escape(caller.file.name.headOption.getOrElse("unknown"))}", "line": ${caller.lineNumber.getOrElse(0)}, "code": "${escape(caller.code)}"}"""
    }.l.mkString(", ")

    s"""{
      "name": "cert-validation-bypass-always-true-callback",
      "file": "${escape(method.file.name.headOption.getOrElse("unknown"))}",
      "line": ${method.lineNumber.getOrElse(0)},
      "endLine": ${method.lineNumber.getOrElse(0)},
      "column": ${method.columnNumber.getOrElse(0)},
      "endColumn": ${method.columnNumber.getOrElse(0)},
      "code": "${escape(method.code)}",
      "severity": "critical",
      "flow": [${callers}]
    }"""
  }

  // Pattern 3: SSL_CTX_set_cert_verify_callback with a callback that always returns 1.
  val certVerifyCallbackRefs = cpg.call
    .nameExact("SSL_CTX_set_cert_verify_callback")
    .argument
    .argumentIndex(2)
    .isIdentifier

  val certVerifyCallbackNames = certVerifyCallbackRefs.name.l.toSet

  val alwaysTrueCertVerify = cpg.method
    .filter(m => certVerifyCallbackNames.contains(m.name))
    .filter { m =>
      val returns = m.ast.isReturn.l
      returns.nonEmpty && returns.forall { ret =>
        ret.astChildren.isLiteral.code.l.exists(c => c == "1" || c == "(1)")
      }
    }

  val certVerifyFindings = alwaysTrueCertVerify.map { method =>
    s"""{
      "name": "cert-validation-bypass-cert-verify-callback",
      "file": "${escape(method.file.name.headOption.getOrElse("unknown"))}",
      "line": ${method.lineNumber.getOrElse(0)},
      "endLine": ${method.lineNumber.getOrElse(0)},
      "column": ${method.columnNumber.getOrElse(0)},
      "endColumn": ${method.columnNumber.getOrElse(0)},
      "code": "${escape(method.code)}",
      "severity": "critical",
      "flow": []
    }"""
  }

  val allFindings = verifyNoneFindings.l ++ callbackFindings.l ++ certVerifyFindings.l
  val json = s"""{"findings": [${allFindings.mkString(",\n")}]}"""
  json |> outFile
}

def escape(s: String): String = {
  s.replace("\\", "\\\\")
   .replace("\"", "\\\"")
   .replace("\n", "\\n")
   .replace("\r", "\\r")
   .replace("\t", "\\t")
}
