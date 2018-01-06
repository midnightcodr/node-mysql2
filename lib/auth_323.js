// https://github.com/mysqljs/mysql/blob/master/lib/protocol/Auth.js

var Buffer = require('safe-buffer').Buffer;
var Crypto = require('crypto');
var Auth = {};

function sha1(msg) {
  var hash = Crypto.createHash('sha1');
  hash.update(msg, 'binary');
  return hash.digest('binary');
}
Auth.sha1 = sha1;

function xor(a, b) {
  a = Buffer.from(a, 'binary');
  b = Buffer.from(b, 'binary');
  var result = Buffer.allocUnsafe(a.length);
  for (var i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}
Auth.xor = xor;

Auth.token = function(password, scramble) {
  if (!password) {
    return Buffer.alloc(0);
  }

  // password must be in binary format, not utf8
  var stage1 = sha1(Buffer.from(password, 'utf8').toString('binary'));
  var stage2 = sha1(stage1);
  var stage3 = sha1(scramble.toString('binary') + stage2);
  return xor(stage3, stage1);
};

// This is a port of sql/password.c:hash_password which needs to be used for
// pre-4.1 passwords.
Auth.hashPassword = function(password) {
  var nr = [0x5030, 0x5735],
    add = 7,
    nr2 = [0x1234, 0x5671],
    result = Buffer.alloc(8);

  if (typeof password === 'string') {
    password = Buffer.from(password);
  }

  for (var i = 0; i < password.length; i++) {
    var c = password[i];
    if (c === 32 || c === 9) {
      // skip space in password
      continue;
    }

    // nr^= (((nr & 63)+add)*c)+ (nr << 8);
    // nr = xor(nr, add(mul(add(and(nr, 63), add), c), shl(nr, 8)))
    nr = Auth.xor32(
      nr,
      Auth.add32(
        Auth.mul32(Auth.add32(Auth.and32(nr, [0, 63]), [0, add]), [0, c]),
        Auth.shl32(nr, 8)
      )
    );

    // nr2+=(nr2 << 8) ^ nr;
    // nr2 = add(nr2, xor(shl(nr2, 8), nr))
    nr2 = Auth.add32(nr2, Auth.xor32(Auth.shl32(nr2, 8), nr));

    // add+=tmp;
    add += c;
  }

  Auth.int31Write(result, nr, 0);
  Auth.int31Write(result, nr2, 4);

  return result;
};

Auth.randomInit = function(seed1, seed2) {
  return {
    max_value: 0x3fffffff,
    max_value_dbl: 0x3fffffff,
    seed1: seed1 % 0x3fffffff,
    seed2: seed2 % 0x3fffffff
  };
};

Auth.myRnd = function(r) {
  r.seed1 = (r.seed1 * 3 + r.seed2) % r.max_value;
  r.seed2 = (r.seed1 + r.seed2 + 33) % r.max_value;

  return r.seed1 / r.max_value_dbl;
};

Auth.scramble323 = function(message, password) {
  var to = Buffer.allocUnsafe(8),
    hashPass = Auth.hashPassword(password),
    hashMessage = Auth.hashPassword(message.slice(0, 8)),
    seed1 = Auth.int32Read(hashPass, 0) ^ Auth.int32Read(hashMessage, 0),
    seed2 = Auth.int32Read(hashPass, 4) ^ Auth.int32Read(hashMessage, 4),
    r = Auth.randomInit(seed1, seed2);

  for (var i = 0; i < 8; i++) {
    to[i] = Math.floor(Auth.myRnd(r) * 31) + 64;
  }
  var extra = Math.floor(Auth.myRnd(r) * 31);

  for (var i = 0; i < 8; i++) {
    to[i] ^= extra;
  }

  return to;
};

Auth.xor32 = function(a, b) {
  return [a[0] ^ b[0], a[1] ^ b[1]];
};

Auth.add32 = function(a, b) {
  var w1 = a[1] + b[1],
    w2 = a[0] + b[0] + ((w1 & 0xffff0000) >> 16);

  return [w2 & 0xffff, w1 & 0xffff];
};

Auth.mul32 = function(a, b) {
  // based on this example of multiplying 32b ints using 16b
  // http://www.dsprelated.com/showmessage/89790/1.php
  var w1 = a[1] * b[1],
    w2 =
      (((a[1] * b[1]) >> 16) & 0xffff) +
      ((a[0] * b[1]) & 0xffff) +
      ((a[1] * b[0]) & 0xffff);

  return [w2 & 0xffff, w1 & 0xffff];
};

Auth.and32 = function(a, b) {
  return [a[0] & b[0], a[1] & b[1]];
};

Auth.shl32 = function(a, b) {
  // assume b is 16 or less
  var w1 = a[1] << b,
    w2 = (a[0] << b) | ((w1 & 0xffff0000) >> 16);

  return [w2 & 0xffff, w1 & 0xffff];
};

Auth.int31Write = function(buffer, number, offset) {
  buffer[offset] = (number[0] >> 8) & 0x7f;
  buffer[offset + 1] = number[0] & 0xff;
  buffer[offset + 2] = (number[1] >> 8) & 0xff;
  buffer[offset + 3] = number[1] & 0xff;
};

Auth.int32Read = function(buffer, offset) {
  return (
    (buffer[offset] << 24) +
    (buffer[offset + 1] << 16) +
    (buffer[offset + 2] << 8) +
    buffer[offset + 3]
  );
};

module.exports.scramble323 = Auth.scramble323;
