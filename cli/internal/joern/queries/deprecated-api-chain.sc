// deprecated-api-chain.sc — Deprecated OpenSSL API usage detection.
//
// Detects usage of deprecated/insecure OpenSSL APIs in call chains:
// DES_*, RC4, MD5_Init, SHA1_Init and related functions.
// These algorithms are cryptographically broken or deprecated.
//
// Output: JSON with findings array containing file, line, code, severity, and flow hops.

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  // Deprecated DES functions (all DES_* variants).
  val desCalls = cpg.call
    .filter(_.name.matches("DES_.*"))

  // RC4 functions.
  val rc4Calls = cpg.call
    .filter(_.name.matches("(?i)RC4.*"))

  // MD5 functions (MD5_Init, MD5_Update, MD5_Final, MD5()).
  val md5Calls = cpg.call
    .filter(_.name.matches("MD5(_Init|_Update|_Final)?"))

  // SHA1 functions (SHA1_Init, SHA1_Update, SHA1_Final, SHA1()).
  val sha1Calls = cpg.call
    .filter(_.name.matches("SHA1(_Init|_Update|_Final)?"))

  // Also flag EVP usage of deprecated algorithms via EVP_md5(), EVP_sha1(),
  // EVP_des_*(), EVP_rc4().
  val evpDeprecated = cpg.call
    .filter(_.name.matches("EVP_(md5|sha1|des_.*|rc4)"))

  // BF_* (Blowfish) — considered weak for modern use.
  val bfCalls = cpg.call
    .filter(_.name.matches("BF_.*"))

  // Collect all deprecated calls.
  val allDeprecated = desCalls ++ rc4Calls ++ md5Calls ++ sha1Calls ++ evpDeprecated ++ bfCalls

  // For each deprecated call, trace call chains (callers) to provide context
  // on how the deprecated API is reached.
  val findings = allDeprecated.map { call =>
    val callerChain = call.method.callIn.map { caller =>
      s"""{"file": "${escape(caller.file.name.headOption.getOrElse("unknown"))}", "line": ${caller.lineNumber.getOrElse(0)}, "code": "${escape(caller.code)}"}"""
    }.l

    val severity = call.name match {
      case n if n.startsWith("DES_") => "critical"    // DES is broken
      case n if n.matches("MD5.*") => "high"           // MD5 collision attacks
      case n if n.matches("SHA1.*") => "high"          // SHA1 collision attacks
      case n if n.matches("(?i)RC4.*") => "critical"   // RC4 is broken
      case n if n.matches("EVP_des_.*") => "critical"  // DES via EVP
      case n if n == "EVP_md5" => "high"               // MD5 via EVP
      case n if n == "EVP_sha1" => "high"              // SHA1 via EVP
      case n if n == "EVP_rc4" => "critical"           // RC4 via EVP
      case n if n.startsWith("BF_") => "medium"        // Blowfish is weak
      case _ => "high"
    }

    val algoName = call.name match {
      case n if n.startsWith("DES_") || n.startsWith("EVP_des") => "DES"
      case n if n.matches("MD5.*") || n == "EVP_md5" => "MD5"
      case n if n.matches("SHA1.*") || n == "EVP_sha1" => "SHA-1"
      case n if n.matches("(?i)RC4.*") || n == "EVP_rc4" => "RC4"
      case n if n.startsWith("BF_") => "Blowfish"
      case _ => "deprecated-algorithm"
    }

    val hops = if (callerChain.nonEmpty) callerChain.mkString(", ") else ""

    s"""{
      "name": "deprecated-api-${algoName}",
      "file": "${escape(call.file.name.headOption.getOrElse("unknown"))}",
      "line": ${call.lineNumber.getOrElse(0)},
      "endLine": ${call.lineNumber.getOrElse(0)},
      "column": ${call.columnNumber.getOrElse(0)},
      "endColumn": ${call.columnNumber.getOrElse(0)},
      "code": "${escape(call.code)}",
      "severity": "${severity}",
      "flow": [${hops}]
    }"""
  }

  val json = s"""{"findings": [${findings.l.mkString(",\n")}]}"""
  json |> outFile
}

def escape(s: String): String = {
  s.replace("\\", "\\\\")
   .replace("\"", "\\\"")
   .replace("\n", "\\n")
   .replace("\r", "\\r")
   .replace("\t", "\\t")
}
