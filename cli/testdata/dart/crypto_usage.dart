import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:encrypt/encrypt.dart';

// ---------------------------------------------------------------------------
// package:crypto — Hashes
// ---------------------------------------------------------------------------

// SHA-256
var sha256Result = sha256.convert(utf8.encode('data'));

// SHA-1 (broken — should be HIGH severity)
var sha1Result = sha1.convert(utf8.encode('data'));

// MD5 (broken — should be HIGH severity)
var md5Result = md5.convert(utf8.encode('data'));

// ---------------------------------------------------------------------------
// package:crypto — HMAC
// ---------------------------------------------------------------------------

// HMAC-SHA256
var hmacSha256 = Hmac(sha256, utf8.encode('secret_key'));
var hmacDigest = hmacSha256.convert(utf8.encode('message'));

// ---------------------------------------------------------------------------
// pointycastle — Symmetric ciphers
// ---------------------------------------------------------------------------

// AES engine
var aesEngine = AESFastEngine();

// DES engine (broken — should be HIGH severity)
var desEngine = DESEngine();

// ---------------------------------------------------------------------------
// pointycastle — Asymmetric
// ---------------------------------------------------------------------------

// RSA engine
var rsaEngine = RSAEngine();

// ---------------------------------------------------------------------------
// pointycastle — Digests
// ---------------------------------------------------------------------------

// SHA-256 digest
var sha256Digest = SHA256Digest();

// ---------------------------------------------------------------------------
// pointycastle — KDF
// ---------------------------------------------------------------------------

// PBKDF2
var pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));

// ---------------------------------------------------------------------------
// pointycastle — Random
// ---------------------------------------------------------------------------

// Fortuna PRNG
var random = FortunaRandom();

// ---------------------------------------------------------------------------
// package:encrypt
// ---------------------------------------------------------------------------

final key = Key.fromLength(32);
final iv = IV.fromLength(16);
final encrypter = Encrypter(AES(key));
final encrypted = encrypter.encrypt('sensitive data', iv: iv);
