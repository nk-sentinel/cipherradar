# Page snapshot

```yaml
- generic [ref=e4]:
  - generic [ref=e5]: CipherRadar
  - generic [ref=e6]: Cryptographic Asset Intelligence Platform
  - generic [ref=e7]:
    - generic [ref=e8]: Email
    - textbox "Email" [ref=e9]:
      - /placeholder: you@company.com
      - text: admin@cipherradar.local
  - generic [ref=e10]:
    - generic [ref=e11]: Password
    - textbox "Password" [active] [ref=e12]:
      - /placeholder: Enter password
      - text: password
  - button "Sign In" [ref=e13] [cursor=pointer]
  - generic [ref=e14]: or
  - button "Sign in with GitHub SSO" [ref=e15] [cursor=pointer]
  - button "Sign in with SAML / OIDC" [ref=e16] [cursor=pointer]
```