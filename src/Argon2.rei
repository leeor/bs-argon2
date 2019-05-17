type argon2Hash;

type argon2Type =
  | Argon2d
  | Argon2i
  | Argon2id;

type argon2Version =
  | Version10
  | Version13;

type numericLimit = {
  min: int,
  max: int,
};

type defaultOptions = {
  hashLength: int,
  timeCost: int,
  memoryCost: int,
  parallelism: int,
  type_: argon2Type,
  version: argon2Version,
  saltLength: int,
};

type limits = {
  hashLength: numericLimit,
  timeCost: numericLimit,
  memoryCost: numericLimit,
  parallelism: numericLimit,
};

let limits: limits;
let defaults: defaultOptions;

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
    [ | `String(string) | `Buffer(Node.Buffer.t)]
  ) =>
  Js.Promise.t(argon2Hash);

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
    [ | `String(string) | `Buffer(Node.Buffer.t)]
  ) =>
  Js.Promise.t(Node.Buffer.t);

let verify:
  (argon2Hash, [ | `String(string) | `Buffer(Node.Buffer.t)]) =>
  Js.Promise.t(bool);

let needsRehash:
  (
    ~timeCost: int=?,
    ~memoryCost: int=?,
    ~version: argon2Version=?,
    argon2Hash
  ) =>
  bool;

let hashToJson: argon2Hash => Js.Json.t;
let jsonToHash: Js.Json.t => argon2Hash;
