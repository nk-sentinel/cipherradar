// hardcoded-secret-flow.sc — Hardcoded secret propagation detection.
//
// Detects hardcoded strings flowing into HMAC(), EVP_DigestSignInit(),
// or password parameters across function boundaries.
//
// Output: JSON with findings array containing file, line, code, severity, and flow hops.

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  implicit val engineContext: EngineContext = EngineContext()

  // Sources: string literals that look like hardcoded secrets.
  // Match string literals >= 6 chars (potential passwords/secrets).
  val stringLiteralSources = cpg.literal
    .filter(_.code.matches("""\"[^\"]{6,}\""""))

  // Variables named with secret-like identifiers assigned from literals.
  val secretVarSources = cpg.local
    .filter(_.name.matches("(?i).*(secret|password|passwd|hmac_key|auth_key|signing_key|passphrase).*"))
    .where(_.refsTo.isLiteral)
    .refsTo.isLiteral

  val allSources = stringLiteralSources ++ secretVarSources

  // Sinks:
  // HMAC() — key parameter (argument index 2, the key data; 1-based)
  val hmacKeySinks = cpg.call
    .nameExact("HMAC")
    .argument
    .argumentIndex(2) // 2nd arg: key pointer

  // EVP_DigestSignInit() — pkey parameter (argument index 5, 1-based)
  val evpDigestSignSinks = cpg.call
    .nameExact("EVP_DigestSignInit")
    .argument
    .argumentIndex(5) // 5th arg: EVP_PKEY (often loaded from hardcoded material)

  // Password-like parameters in common auth/crypto functions.
  val passwordSinks = cpg.call
    .filter(_.name.matches("(?i).*(password|passwd|authenticate|login|crypt).*"))
    .argument
    .argumentIndex(1)

  // PKCS5_PBKDF2_HMAC — password parameter (argument index 1, 1-based)
  val pbkdf2Sinks = cpg.call
    .nameExact("PKCS5_PBKDF2_HMAC")
    .argument
    .argumentIndex(1)

  val allSinks = hmacKeySinks ++ evpDigestSignSinks ++ passwordSinks ++ pbkdf2Sinks

  // Run inter-procedural reachability analysis.
  val flows = allSinks.reachableBy(allSources).flows

  val findings = flows.map { flow =>
    val source = flow.elements.head
    val sink = flow.elements.last
    val hops = flow.elements.map { elem =>
      s"""{"file": "${escape(elem.file.name.headOption.getOrElse("unknown"))}", "line": ${elem.lineNumber.getOrElse(0)}, "code": "${escape(elem.code)}"}"""
    }.mkString(", ")

    val sinkCall = sink.astParent match {
      case call: io.shiftleft.codepropertygraph.generated.nodes.Call => call.name
      case _ => "secret-sink"
    }

    s"""{
      "name": "hardcoded-secret-to-${sinkCall}",
      "file": "${escape(sink.file.name.headOption.getOrElse("unknown"))}",
      "line": ${sink.lineNumber.getOrElse(0)},
      "endLine": ${sink.lineNumber.getOrElse(0)},
      "column": ${sink.columnNumber.getOrElse(0)},
      "endColumn": ${sink.columnNumber.getOrElse(0)},
      "code": "${escape(sink.code)}",
      "severity": "high",
      "flow": [${hops}]
    }"""
  }

  val json = s"""{"findings": [${findings.mkString(",\n")}]}"""
  json |> outFile
}

def escape(s: String): String = {
  s.replace("\\", "\\\\")
   .replace("\"", "\\\"")
   .replace("\n", "\\n")
   .replace("\r", "\\r")
   .replace("\t", "\\t")
}
