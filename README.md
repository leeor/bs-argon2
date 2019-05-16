# BuckleScript Bindings for Argon2

Based on [node-argon2](https://github.com/ranisalt/node-argon2).

## API

### hashString & hashBuffer

Hash a `string` or a `Node.Buffer.t`, respectively, returning a `argon2Hash`.

```Reason
let hashString:
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
    string
  ) =>
  Js.Promise.t(argon2Hash);

let hashBuffer:
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
    Node.Buffer.t
  ) =>
  Js.Promise.t(argon2Hash);
```

### hashStringRaw & hashBufferRaw

Hash a `string` or a `Node.Buffer.t`, respectively, returning a `Node.Buffer.t`.

```Reason
let hashStringRaw:
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
    string
  ) =>
  Js.Promise.t(Node.Buffer.t);

let hashBufferRaw:
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
    Node.Buffer.t
  ) =>
  Js.Promise.t(Node.Buffer.t);
```

### needsRehash

Return whether the has needs to be recomputed due to changed options/version.

```Reason
let needsRehash:
  (~timeCost: int=?, ~memoryCost: int=?, ~version: argon2Version=?, argon2Hash) =>
  bool;
```

### verifyString & verifyBuffer

Verify a given `string` or `Node.Buffer.t`, respectively, against a previously generated hash.

```Reason
let verifyString: (argon2Hash, string) => Js.Promise.t(bool);

let verifyBuffer: (argon2Hash, Node.Buffer.t) => Js.Promise.t(bool);
```
