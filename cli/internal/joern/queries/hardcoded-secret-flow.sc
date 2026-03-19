// hardcoded-secret-flow.sc — Hardcoded secret propagation detection.
//
// This Joern query identifies data flows where hardcoded secrets
// (string literals matching secret patterns) propagate across function
// boundaries into security-sensitive sinks such as encryption, HMAC,
// or authentication APIs.
//
// Output: JSON array of findings with file, line, code, and flow hops.
//
// Placeholder — to be implemented with full CPG taint queries.

@main def main(cpg: String): Unit = {
  // TODO: Load CPG and run inter-procedural taint analysis
  // for hardcoded secrets flowing into crypto/auth sinks.
  println("{\"findings\": []}")
}
