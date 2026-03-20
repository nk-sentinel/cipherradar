// iv-reuse.sc — Static/constant IV reuse detection.
//
// Detects static or constant initialization vectors flowing into the IV
// parameter of EVP_EncryptInit_ex. Reusing a static IV with the same key
// breaks the semantic security of CBC/CTR/GCM modes.
//
// Output: JSON with findings array containing file, line, code, severity, and flow hops.

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  implicit val engineContext: EngineContext = EngineContext()

  // Sources: static/constant IVs.
  // String literals (hardcoded IV bytes).
  val stringIVSources = cpg.literal
    .filter(_.code.matches("""\"[^\"]+\""""))

  // Byte array initializers used as IVs.
  val arrayIVSources = cpg.call
    .nameExact("<operator>.arrayInitializer")

  // Variables explicitly named as IV/nonce assigned from constants.
  val namedIVSources = cpg.local
    .filter(_.name.matches("(?i).*(iv|nonce|init_vec|initialization_vector).*"))
    .where(_.refsTo.isLiteral)
    .refsTo.isLiteral

  // Global/static const arrays (often used for fixed IVs).
  val globalIVSources = cpg.member
    .filter(_.name.matches("(?i).*(iv|nonce|init_vec).*"))
    .where(_.astParent.isTypeDecl)

  val allSources = stringIVSources ++ arrayIVSources ++ namedIVSources

  // Sinks: the IV parameter of EVP_EncryptInit_ex.
  // EVP_EncryptInit_ex(ctx, type, impl, key, iv) — iv is argument index 5 (1-based).
  val evpIVSinks = cpg.call
    .nameExact("EVP_EncryptInit_ex")
    .argument
    .argumentIndex(5) // 5th argument is the IV

  // Also check EVP_EncryptInit (older API).
  // EVP_EncryptInit(ctx, type, key, iv) — iv is argument index 4 (1-based).
  val evpInitIVSinks = cpg.call
    .nameExact("EVP_EncryptInit")
    .argument
    .argumentIndex(4)

  // EVP_CipherInit_ex iv parameter (argument index 5, 1-based).
  val cipherInitIVSinks = cpg.call
    .nameExact("EVP_CipherInit_ex")
    .argument
    .argumentIndex(5)

  val allSinks = evpIVSinks ++ evpInitIVSinks ++ cipherInitIVSinks

  // Run inter-procedural reachability analysis.
  val flows = allSinks.reachableBy(allSources).flows

  val findings = flows.map { flow =>
    val source = flow.elements.head
    val sink = flow.elements.last
    val hops = flow.elements.map { elem =>
      s"""{"file": "${escape(elem.file.name.headOption.getOrElse("unknown"))}", "line": ${elem.lineNumber.getOrElse(0)}, "code": "${escape(elem.code)}"}"""
    }.mkString(", ")

    s"""{
      "name": "static-iv-reuse",
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
