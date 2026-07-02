import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SharingFixtureVerifier {
  private static final Base64.Decoder BASE64_URL = Base64.getUrlDecoder();

  public static void main(String[] arguments) throws Exception {
    if (arguments.length != 1) {
      throw new IllegalArgumentException("Expected one sharing fixture path.");
    }
    Map<String, Object> fixture = object(
        new JsonParser(Files.readString(Path.of(arguments[0]))).parse());
    Map<String, Object> viewer = object(fixture.get("viewer"));
    Map<String, Object> viewerPublic = object(viewer.get("publicKey"));
    Map<String, Object> privateKeys = object(viewer.get("privateKeys"));
    Map<String, Object> encryptionPrivate = object(privateKeys.get("encryption"));
    Map<String, Object> envelope = object(fixture.get("envelope"));
    String recipientKeyId = string(viewerPublic.get("keyId"));

    Map<String, Object> grant = list(envelope.get("keyGrants")).stream()
        .map(SharingFixtureVerifier::object)
        .filter(candidate ->
            recipientKeyId.equals(string(candidate.get("recipientKeyId"))))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("Viewer grant missing."));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec p256 = parameters.getParameterSpec(ECParameterSpec.class);
    var privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(
        new BigInteger(1, decode(string(encryptionPrivate.get("d")))),
        p256));
    var ephemeralPublicKey = publicKey(
        decode(string(grant.get("ephemeralPublicKey"))),
        keyFactory,
        p256);
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(privateKey);
    agreement.doPhase(ephemeralPublicKey, true);
    byte[] sharedSecret = agreement.generateSecret();

    Map<String, Object> grantHeader = new TreeMap<>();
    grantHeader.put("appId", envelope.get("appId"));
    grantHeader.put("backupId", envelope.get("backupId"));
    grantHeader.put("ephemeralPublicKey", grant.get("ephemeralPublicKey"));
    grantHeader.put("kdfSalt", grant.get("kdfSalt"));
    grantHeader.put("nonce", grant.get("nonce"));
    grantHeader.put("recipientKeyId", grant.get("recipientKeyId"));
    grantHeader.put("revisionId", envelope.get("revisionId"));
    byte[] wrappingKey = hkdf(
        sharedSecret,
        decode(string(grant.get("kdfSalt"))),
        ("sync-kit-sharing-v1:" + canonicalJson(grantHeader))
            .getBytes(StandardCharsets.UTF_8),
        32);
    byte[] contentKey = decryptAesGcm(
        wrappingKey,
        decode(string(grant.get("nonce"))),
        canonicalJson(grantHeader).getBytes(StandardCharsets.UTF_8),
        decode(string(grant.get("wrappedContentKey"))));

    Map<String, Object> payloadHeader = new TreeMap<>();
    for (String field : List.of(
        "schemaVersion",
        "kind",
        "algorithm",
        "appId",
        "backupId",
        "revisionId",
        "parentRevisionId",
        "revisionAncestors",
        "createdAt",
        "authorKeyId")) {
      if (envelope.containsKey(field)) payloadHeader.put(field, envelope.get(field));
    }
    byte[] plaintext = decryptAesGcm(
        contentKey,
        decode(string(envelope.get("payloadNonce"))),
        canonicalJson(payloadHeader).getBytes(StandardCharsets.UTF_8),
        decode(string(envelope.get("ciphertext"))));
    Object payload = new JsonParser(
        new String(plaintext, StandardCharsets.UTF_8)).parse();
    if (!canonicalJson(payload).equals(canonicalJson(fixture.get("payload")))) {
      throw new IllegalStateException("Native payload does not match fixture.");
    }

    Map<String, Object> unsignedEnvelope = new TreeMap<>(envelope);
    unsignedEnvelope.remove("signature");
    Map<String, Object> currentAccess = object(
        list(envelope.get("accessControl")).get(
            list(envelope.get("accessControl")).size() - 1));
    Map<String, Object> author = list(currentAccess.get("participants")).stream()
        .map(SharingFixtureVerifier::object)
        .filter(participant ->
            string(envelope.get("authorKeyId"))
                .equals(string(participant.get("keyId"))))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("Author missing."));
    Signature signature = Signature.getInstance(
        "SHA256withECDSAinP1363Format");
    signature.initVerify(publicKey(
        decode(string(author.get("signingPublicKey"))),
        keyFactory,
        p256));
    signature.update(
        canonicalJson(unsignedEnvelope).getBytes(StandardCharsets.UTF_8));
    if (!signature.verify(decode(string(envelope.get("signature"))))) {
      throw new IllegalStateException("Native envelope signature failed.");
    }

    System.out.println("Java sharing fixture verified.");
  }

  private static java.security.PublicKey publicKey(
      byte[] raw,
      KeyFactory keyFactory,
      ECParameterSpec parameters) throws Exception {
    if (raw.length != 65 || raw[0] != 4) {
      throw new IllegalArgumentException("Expected uncompressed P-256 key.");
    }
    byte[] x = java.util.Arrays.copyOfRange(raw, 1, 33);
    byte[] y = java.util.Arrays.copyOfRange(raw, 33, 65);
    return keyFactory.generatePublic(new ECPublicKeySpec(
        new ECPoint(new BigInteger(1, x), new BigInteger(1, y)),
        parameters));
  }

  private static byte[] decryptAesGcm(
      byte[] key,
      byte[] nonce,
      byte[] aad,
      byte[] ciphertext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aad);
    return cipher.doFinal(ciphertext);
  }

  private static byte[] hkdf(
      byte[] ikm,
      byte[] salt,
      byte[] info,
      int length) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(salt, "HmacSHA256"));
    byte[] prk = mac.doFinal(ikm);
    byte[] output = new byte[length];
    byte[] previous = new byte[0];
    int offset = 0;
    int counter = 1;
    while (offset < length) {
      mac.init(new SecretKeySpec(prk, "HmacSHA256"));
      mac.update(previous);
      mac.update(info);
      mac.update((byte) counter++);
      previous = mac.doFinal();
      int copied = Math.min(previous.length, length - offset);
      System.arraycopy(previous, 0, output, offset, copied);
      offset += copied;
    }
    java.util.Arrays.fill(prk, (byte) 0);
    return output;
  }

  private static byte[] decode(String value) {
    return BASE64_URL.decode(value);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(Object value) {
    return (List<Object>) value;
  }

  private static String string(Object value) {
    return (String) value;
  }

  private static String canonicalJson(Object value) {
    if (value == null) return "null";
    if (value instanceof String text) return quote(text);
    if (value instanceof Boolean || value instanceof Number) {
      return value.toString();
    }
    if (value instanceof List<?> values) {
      return "[" + values.stream()
          .map(SharingFixtureVerifier::canonicalJson)
          .reduce((left, right) -> left + "," + right)
          .orElse("") + "]";
    }
    if (value instanceof Map<?, ?> values) {
      return "{" + values.entrySet().stream()
          .sorted(Comparator.comparing(entry -> (String) entry.getKey()))
          .map(entry -> quote((String) entry.getKey()) + ":"
              + canonicalJson(entry.getValue()))
          .reduce((left, right) -> left + "," + right)
          .orElse("") + "}";
    }
    throw new IllegalArgumentException("Unsupported JSON value.");
  }

  private static String quote(String value) {
    StringBuilder result = new StringBuilder("\"");
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      switch (character) {
        case '"' -> result.append("\\\"");
        case '\\' -> result.append("\\\\");
        case '\b' -> result.append("\\b");
        case '\f' -> result.append("\\f");
        case '\n' -> result.append("\\n");
        case '\r' -> result.append("\\r");
        case '\t' -> result.append("\\t");
        default -> {
          if (character < 0x20) {
            result.append(String.format("\\u%04x", (int) character));
          } else {
            result.append(character);
          }
        }
      }
    }
    return result.append('"').toString();
  }

  private static final class JsonParser {
    private final String source;
    private int offset;

    private JsonParser(String source) {
      this.source = source;
    }

    private Object parse() {
      Object value = value();
      whitespace();
      if (offset != source.length()) throw error();
      return value;
    }

    private Object value() {
      whitespace();
      if (offset >= source.length()) throw error();
      return switch (source.charAt(offset)) {
        case '{' -> object();
        case '[' -> array();
        case '"' -> string();
        case 't' -> literal("true", true);
        case 'f' -> literal("false", false);
        case 'n' -> literal("null", null);
        default -> number();
      };
    }

    private Map<String, Object> object() {
      offset++;
      Map<String, Object> result = new LinkedHashMap<>();
      whitespace();
      if (take('}')) return result;
      do {
        whitespace();
        String key = string();
        whitespace();
        if (!take(':')) throw error();
        result.put(key, value());
        whitespace();
      } while (take(','));
      if (!take('}')) throw error();
      return result;
    }

    private List<Object> array() {
      offset++;
      List<Object> result = new ArrayList<>();
      whitespace();
      if (take(']')) return result;
      do {
        result.add(value());
        whitespace();
      } while (take(','));
      if (!take(']')) throw error();
      return result;
    }

    private String string() {
      if (!take('"')) throw error();
      StringBuilder result = new StringBuilder();
      while (offset < source.length()) {
        char character = source.charAt(offset++);
        if (character == '"') return result.toString();
        if (character != '\\') {
          result.append(character);
          continue;
        }
        char escaped = source.charAt(offset++);
        switch (escaped) {
          case '"', '\\', '/' -> result.append(escaped);
          case 'b' -> result.append('\b');
          case 'f' -> result.append('\f');
          case 'n' -> result.append('\n');
          case 'r' -> result.append('\r');
          case 't' -> result.append('\t');
          case 'u' -> {
            result.append((char) Integer.parseInt(
                source.substring(offset, offset + 4), 16));
            offset += 4;
          }
          default -> throw error();
        }
      }
      throw error();
    }

    private Object number() {
      int start = offset;
      while (offset < source.length()
          && "-+0123456789.eE".indexOf(source.charAt(offset)) >= 0) {
        offset++;
      }
      String value = source.substring(start, offset);
      if (value.contains(".") || value.contains("e") || value.contains("E")) {
        return Double.valueOf(value);
      }
      return Long.valueOf(value);
    }

    private Object literal(String text, Object value) {
      if (!source.startsWith(text, offset)) throw error();
      offset += text.length();
      return value;
    }

    private boolean take(char character) {
      if (offset < source.length() && source.charAt(offset) == character) {
        offset++;
        return true;
      }
      return false;
    }

    private void whitespace() {
      while (offset < source.length()
          && Character.isWhitespace(source.charAt(offset))) {
        offset++;
      }
    }

    private IllegalArgumentException error() {
      return new IllegalArgumentException("Invalid JSON at " + offset);
    }
  }
}
