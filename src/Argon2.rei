type hash;

type hashMode =
  | Argon2d
  | Argon2i
  | Argon2id;

type version =
  | Version10
  | Version13;

type defaultOptions = {
  hashLength: int,
  timeCost: int,
  memoryCost: int,
  parallelism: int,
  type_: hashMode,
  version,
  saltLength: int,
};

type numericLimit = {
  min: int,
  max: int,
};

type limits = {
  hashLength: numericLimit,
  timeCost: numericLimit,
  memoryCost: numericLimit,
  parallelism: numericLimit,
};

let limits: limits;
let defaults: defaultOptions;

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

let verify: (hash, hashInput) => Js.Promise.t(bool);

let needsRehash:
  (~timeCost: int=?, ~memoryCost: int=?, ~version: version=?, hash) => bool;

let hashToJson: hash => Js.Json.t;
let jsonToHash: Js.Json.t => hash;
