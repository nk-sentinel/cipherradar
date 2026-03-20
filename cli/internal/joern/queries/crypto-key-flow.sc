// crypto-key-flow.sc — Inter-procedural cryptographic key flow detection.
//
// Detects hardcoded key material (string literals, byte arrays) flowing into
// OpenSSL EVP_EncryptInit_ex or AES_set_encrypt_key across function boundaries.
//
// Output: JSON with findings array containing file, line, code, severity, and flow hops.

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  implicit val engineContext: EngineContext = EngineContext()

  // Sources: string literals and byte array initializers that look like key material.
  // Match string literals >= 8 chars (potential key data) and hex-like patterns.
  val stringLiteralSources = cpg.literal
    .filter(_.code.matches("""\"[^\"]{8,}\""""))

  // Byte array sources: declarations with initializer lists resembling key bytes.
  val byteArraySources = cpg.call
    .nameExact("<operator>.arrayInitializer")
    .where(_.argument.isLiteral.size >= 8)

  // Also catch #define or const arrays assigned from hex strings.
  val constKeySources = cpg.local
    .filter(_.name.matches("(?i).*(key|secret|aes_key|enc_key|crypt_key).*"))
    .where(_.refsTo.isLiteral)
    .refsTo.isLiteral

  val allSources = stringLiteralSources ++ byteArraySources ++ constKeySources

  // Sinks: key parameter of EVP_EncryptInit_ex (param index 3, 0-based)
  // and AES_set_encrypt_key (param index 0, 0-based).
  val evpKeySinks = cpg.call
    .nameExact("EVP_EncryptInit_ex")
    .argument
    .argumentIndex(4) // 4th argument is the key (1-based in Joern)

  val aesSetKeySinks = cpg.call
    .nameExact("AES_set_encrypt_key")
    .argument
    .argumentIndex(1) // 1st argument is the key (1-based)

  val allSinks = evpKeySinks ++ aesSetKeySinks

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
      case _ => "crypto-api"
    }

    s"""{
      "name": "hardcoded-key-to-${sinkCall}",
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
