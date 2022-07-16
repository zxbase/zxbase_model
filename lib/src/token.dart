// Copyright (C) 2022 Zxbase, LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// Minimalistic token parsing.
/// Device just needs to be aware of expiration date.
/// String token structure: header.payload.signature
/// Fields are base64url encoded jsons.

import 'dart:convert';
import 'dart:typed_data';

class Token {
  Token.fromString(String token) {
    var fields = token.split('.');

    Uint8List bin = base64Url.decode(fields[1]);
    String str = utf8.decode(bin);
    Map<String, dynamic> json = jsonDecode(str);

    exp = DateTime.fromMillisecondsSinceEpoch(json['exp']).toUtc();
    assert(exp.isUtc);
  }

  late DateTime exp;
}
