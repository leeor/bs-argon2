# BuckleScript Bindings for Argon2

Based on [node-argon2](https://github.com/ranisalt/node-argon2).

## Install

```
npm install @leeor/bs-argon2 --save
```

## API

### The `Argon2.hash` type

To promote security of the generated hashes, a special type is used to represent the output of the hashing functions. This should be used for protecting at the type level against leakage and usage of these values in sensitive areas (such as code that is used by both client and server).

### hash

Hash a `string` or a `Node.Buffer.t` returning an `Argon2.hash`.

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
    ~type_: hashMode=?,
    ~version: version=?,
    ~salt: Node.Buffer.t=?,
    ~saltLength: int=?,
    ~associatedData: Node.Buffer.t=?,
    hashInput
  ) =>
  Js.Promise.t(hash);
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
    ~type_: hashMode=?,
    ~version: version=?,
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
  (~timeCost: int=?, ~memoryCost: int=?, ~version: version=?, hash) =>
  bool;
```

### verify

Verify a given `string` or `Node.Buffer.t` against a previously generated hash.

```Reason
type hashInput =
  | String(string)
  | Buffer(Node.Buffer.t);

let verify: (hash, hashInput) => Js.Promise.t(bool);
```

### Js.Json.t Enconding/decoding

Use the following two functions when (de)serializing generated hashes:

```Reason
let hashToJson: hash => Js.Json.t;
let jsonToHash: Js.Json.t => hash;
```

Note: in its current implementation, `jsonToHash` will raise an exception if the decoding fails.
