import 'dart:convert';
import 'dart:typed_data';

import 'package:zxbase_crypto/zxbase_crypto.dart';
import 'package:cryptography/cryptography.dart';

class Identity {
  // initialize with device Id and public Ed25519 key
  Identity({required this.deviceId, required this.publicKey});
  // version 2 includes username
  Identity.v2(
      {required this.deviceId,
      required this.publicKey,
      required this.username}) {
    version = 2;
  }

  /// Encoding follows JWK format - https://datatracker.ietf.org/doc/html/rfc7517, with addition of version.
  /// {
  ///   ver: 1
  ///   kty: OKP,
  ///   crv: Ed25519,
  ///   x: base64url(key),
  ///   kid: device Id
  /// }
  ///
  /// {
  ///   ver: 2
  ///   kty: OKP,
  ///   crv: Ed25519,
  ///   x: base64url(key),
  ///   kid: device Id
  ///   usr: username
  ///  }
  Identity.fromBase64Url(String msg) {
    Uint8List bin = base64Url.decode(msg);
    String str = utf8.decode(bin);
    Map<String, dynamic> json = jsonDecode(str);

    deviceId = json['kid'];
    publicKey = PKCrypto.jwkToPublicKey(json);
    if (json['ver'] == null) {
      version = 1;
    } else {
      version = json['ver'];
    }
    if (version > 1) {
      username = json['usr'];
    }
  }

  String deviceId = '';
  late SimplePublicKey publicKey;
  late String username;
  int version = 1;

  String toBase64Url() {
    Map<String, dynamic> jwk = PKCrypto.publicKeyToJwk(publicKey);
    jwk['kid'] = deviceId;
    jwk['ver'] = version;
    if (version == 2) {
      jwk['usr'] = username;
    }
    return base64Url.encode(utf8.encode(jsonEncode(jwk)));
  }

  Future<bool> verifySignature(String msg, String sig) async {
    return await PKCrypto.verifySignatureWithPublicKey(msg, sig, publicKey);
  }
}
