import 'package:zxbase_crypto/zxbase_crypto.dart';
import 'package:zxbase_model/zxbase_model.dart';
import 'package:test/test.dart';
import 'package:uuid/uuid.dart';

void main() {
  test('Create identity from dart generated string', () {
    var msg =
        'eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IklVbnliMDRMRWRYS0FLUzNreFNzVmNKRHU0bWJYRFFkUl94aU9Ib1B3cFU9Iiwia2lkIjoiMTQ0YzE4NGUtZTZmMy00YjU1LTg0ZjktZWU3ODdkYzE2YWQ4IiwidmVyIjoxfQ==';
    var idnt = Identity.fromBase64Url(msg);
    expect(idnt.toBase64Url(), equals(msg));
  });

  test('Create identity from node.js string', () async {
    var msg =
        'eyJjcnYiOiJFZDI1NTE5IiwieCI6Imhaa3JyZ3JBWmpqdVhqZmU4X2tfQXV5RVl0OUl0elhLdE9WUUxFOEdScUUiLCJrdHkiOiJPS1AiLCJraWQiOiJkYWUzOGUxMy1hNjI1LTQxMmMtYmVjNS02NTgzZWJiMTNlOWEifQ%3D%3D';
    var idnt = Identity.fromBase64Url(msg);
    expect(idnt.deviceId, equals('dae38e13-a625-412c-bec5-6583ebb13e9a'));
  });

  test('Verify identity signature', () async {
    var deviceId = const Uuid().v4();
    var identityKeyPair = await PKCrypto.generateKeyPair();
    var pubK = await identityKeyPair.extractPublicKey();
    var identity = Identity(deviceId: deviceId, publicKey: pubK);
    expect(identity.deviceId, equals(deviceId));

    var msg = 'Message';
    var sig = await PKCrypto.sign(msg, identityKeyPair);

    expect(await identity.verifySignature(msg, sig), equals(true));
  });

  test('Create v2 identity with username', () async {
    var deviceId = const Uuid().v4();
    var identityKeyPair = await PKCrypto.generateKeyPair();
    var username = 'testUser';
    var pubK = await identityKeyPair.extractPublicKey();
    var identity =
        Identity.v2(deviceId: deviceId, publicKey: pubK, username: username);
    expect(identity.deviceId, equals(deviceId));
    expect(identity.username, equals(username));

    var strIdnt = identity.toBase64Url();
    var idnt2 = Identity.fromBase64Url(strIdnt);

    expect(identity.deviceId, equals(idnt2.deviceId));
    expect(identity.username, equals(idnt2.username));
  });
}
