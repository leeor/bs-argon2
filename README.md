# BuckleScript Bindings for Argon2

Based on [node-argon2](https://github.com/ranisalt/node-argon2).

## Install

```
npm install @leeor/bs-argon2 --save
```

## API

### hash

Hash a `string` or a `Node.Buffer.t` returning an `argon2Hash`.

```Reason
type hashInput =
  | String(string)
  | Buffer(Node.Buffer.t);

let hash:
  (
    ~hashLength: int=?,
    ~timeCost: int=?,
    ~memoryCost: int=?,
    ~parallelism: int=?,
    ~type_: argon2Type=?,
    ~version: argon2Version=?,
    ~salt: Node.Buffer.t=?,
    ~saltLength: int=?,
    ~associatedData: Node.Buffer.t=?,
    hashInput
  ) =>
  Js.Promise.t(argon2Hash);
```

### hashRaw

Hash a `string` or a `Node.Buffer.t` returning a `Node.Buffer.t`.

```Reason
type hashInput =
  | String(string)
  | Buffer(Node.Buffer.t);

let hashRaw:
  (
    ~hashLength: int=?,
    ~timeCost: int=?,
    ~memoryCost: int=?,
    ~parallelism: int=?,
    ~type_: argon2Type=?,
    ~version: argon2Version=?,
    ~salt: Node.Buffer.t=?,
    ~saltLength: int=?,
    ~associatedData: Node.Buffer.t=?,
    hashInput
  ) =>
  Js.Promise.t(Node.Buffer.t);
```

### needsRehash

Return whether the hash needs to be recomputed due to changed options/version.

```Reason
let needsRehash:
  (~timeCost: int=?, ~memoryCost: int=?, ~version: argon2Version=?, argon2Hash) =>
  bool;
```

### verify

Verify a given `string` or `Node.Buffer.t` against a previously generated hash.

```Reason
type hashInput =
  | String(string)
  | Buffer(Node.Buffer.t);

let verify: (argon2Hash, hashInput) => Js.Promise.t(bool);
```
