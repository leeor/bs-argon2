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
  Js.Promise.t(string);

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
  Js.Promise.t(string);

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

let verifyString: (string, string) => Js.Promise.t(bool);
let verifyBuffer: (string, Node.Buffer.t) => Js.Promise.t(bool);

let needsRehash:
  (~timeCost: int=?, ~memoryCost: int=?, ~version: argon2Version=?, string) =>
  bool;
