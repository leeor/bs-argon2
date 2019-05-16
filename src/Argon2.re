type argon2Hash = string;

[@bs.deriving abstract]
type options = {
  [@bs.optional]
  hashLength: int,
  [@bs.optional]
  timeCost: int,
  [@bs.optional]
  memoryCost: int,
  [@bs.optional]
  parallelism: int,
  [@bs.optional] [@bs.as "type"]
  type_: int,
  [@bs.optional]
  version: int,
  [@bs.optional]
  salt: Node.Buffer.t,
  [@bs.optional]
  associatedData: Node.Buffer.t,
  [@bs.optional]
  saltLength: int,
  raw: bool,
};

[@bs.deriving jsConverter]
type argon2Type =
  | Argon2d
  | Argon2i
  | Argon2id;

[@bs.deriving jsConverter]
type argon2Version =
  | [@bs.as 0x10] Version10
  | [@bs.as 0x13] Version13;

type defaultOptions = {
  hashLength: int,
  timeCost: int,
  memoryCost: int,
  parallelism: int,
  type_: argon2Type,
  version: argon2Version,
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

[@bs.module "argon2"] external limits_: Js.Json.t = "limits";
[@bs.module "argon2"] external defaults_: Js.Json.t = "defaults";

let decodedLimits =
  limits_
  |> Js.Json.decodeObject
  |> Belt.Option.getWithDefault(_, Js.Dict.empty());

let decodeNumericLimits = json => {
  let limits =
    json
    |> Js.Json.decodeObject
    |> Belt.Option.getWithDefault(_, Js.Dict.empty());

  {
    min:
      limits
      |> Js.Dict.get(_, "min")
      |> Belt.Option.getWithDefault(_, Js.Json.number(0.))
      |> Js.Json.decodeNumber
      |> Belt.Option.getWithDefault(_, 0.)
      |> int_of_float,
    max:
      limits
      |> Js.Dict.get(_, "max")
      |> Belt.Option.getWithDefault(_, Js.Json.number(0.))
      |> Js.Json.decodeNumber
      |> Belt.Option.getWithDefault(_, 0.)
      |> int_of_float,
  };
};

let limits = {
  hashLength:
    decodedLimits
    |> Js.Dict.get(_, "hashLength")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> decodeNumericLimits,
  timeCost:
    decodedLimits
    |> Js.Dict.get(_, "timeCost")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> decodeNumericLimits,
  memoryCost:
    decodedLimits
    |> Js.Dict.get(_, "memoryCost")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> decodeNumericLimits,
  parallelism:
    decodedLimits
    |> Js.Dict.get(_, "parallelism")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> decodeNumericLimits,
};

let decodedDefaults =
  defaults_
  |> Js.Json.decodeObject
  |> Belt.Option.getWithDefault(_, Js.Dict.empty());

let defaults = {
  hashLength:
    decodedDefaults
    |> Js.Dict.get(_, "hashLength")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float,
  timeCost:
    decodedDefaults
    |> Js.Dict.get(_, "timeCost")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float,
  memoryCost:
    decodedDefaults
    |> Js.Dict.get(_, "memoryCost")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float,
  parallelism:
    decodedDefaults
    |> Js.Dict.get(_, "parallelism")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float,
  type_:
    decodedDefaults
    |> Js.Dict.get(_, "type")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float
    |> (
      fun
      | 0 => Argon2d
      | 1 => Argon2i
      | 2 => Argon2id
      | _ => Js.Exn.raiseError("unknown Argon2 type")
    ),
  version:
    decodedDefaults
    |> Js.Dict.get(_, "version")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float
    |> (
      fun
      | 0x10 => Version10
      | 0x13 => Version13
      | _ => Js.Exn.raiseError("unknown Argon2 version")
    ),
  saltLength:
    decodedDefaults
    |> Js.Dict.get(_, "saltLength")
    |> Belt.Option.getWithDefault(_, Js.Json.object_(Js.Dict.empty()))
    |> Js.Json.decodeNumber
    |> Belt.Option.getWithDefault(_, 0.)
    |> int_of_float,
};

[@bs.module "argon2"]
external hashStringRaw: (string, options) => Js.Promise.t(Node.Buffer.t) =
  "hash";

[@bs.module "argon2"]
external hashBufferRaw:
  (Node.Buffer.t, options) => Js.Promise.t(Node.Buffer.t) =
  "hash";

[@bs.module "argon2"]
external hashString: (string, options) => Js.Promise.t(argon2Hash) = "hash";

[@bs.module "argon2"]
external hashBuffer: (Node.Buffer.t, options) => Js.Promise.t(argon2Hash) =
  "hash";

[@bs.module "argon2"]
external verifyString: (argon2Hash, string) => Js.Promise.t(bool) = "verify";

[@bs.module "argon2"]
external verifyBuffer: (argon2Hash, Node.Buffer.t) => Js.Promise.t(bool) =
  "verify";

[@bs.module "argon2"] external needsRehash: (argon2Hash, options) => bool = "";

let hashString =
    (
      ~hashLength: option(int)=?,
      ~timeCost: option(int)=?,
      ~memoryCost: option(int)=?,
      ~parallelism: option(int)=?,
      ~type_: option(argon2Type)=?,
      ~version: option(argon2Version)=?,
      ~salt: option(Node.Buffer.t)=?,
      ~saltLength: option(int)=?,
      ~associatedData: option(Node.Buffer.t)=?,
      str,
    ) => {
  let hashOptions =
    options(
      ~hashLength?,
      ~timeCost?,
      ~memoryCost?,
      ~parallelism?,
      ~type_=?
        switch (type_) {
        | Some(t) => Some(argon2TypeToJs(t))
        | None => None
        },
      ~version=?
        switch (version) {
        | Some(v) => Some(argon2VersionToJs(v))
        | None => None
        },
      ~salt?,
      ~saltLength?,
      ~associatedData?,
      ~raw=false,
      (),
    );

  hashString(str, hashOptions);
};

let hashBuffer =
    (
      ~hashLength: option(int)=?,
      ~timeCost: option(int)=?,
      ~memoryCost: option(int)=?,
      ~parallelism: option(int)=?,
      ~type_: option(argon2Type)=?,
      ~version: option(argon2Version)=?,
      ~salt: option(Node.Buffer.t)=?,
      ~saltLength: option(int)=?,
      ~associatedData: option(Node.Buffer.t)=?,
      buffer,
    ) => {
  let hashOptions =
    options(
      ~hashLength?,
      ~timeCost?,
      ~memoryCost?,
      ~parallelism?,
      ~type_=?
        switch (type_) {
        | Some(t) => Some(argon2TypeToJs(t))
        | None => None
        },
      ~version=?
        switch (version) {
        | Some(v) => Some(argon2VersionToJs(v))
        | None => None
        },
      ~salt?,
      ~saltLength?,
      ~associatedData?,
      ~raw=false,
      (),
    );

  hashBuffer(buffer, hashOptions);
};

let hashStringRaw =
    (
      ~hashLength: option(int)=?,
      ~timeCost: option(int)=?,
      ~memoryCost: option(int)=?,
      ~parallelism: option(int)=?,
      ~type_: option(argon2Type)=?,
      ~version: option(argon2Version)=?,
      ~salt: option(Node.Buffer.t)=?,
      ~saltLength: option(int)=?,
      ~associatedData: option(Node.Buffer.t)=?,
      str,
    ) => {
  let hashOptions =
    options(
      ~hashLength?,
      ~timeCost?,
      ~memoryCost?,
      ~parallelism?,
      ~type_=?
        switch (type_) {
        | Some(t) => Some(argon2TypeToJs(t))
        | None => None
        },
      ~version=?
        switch (version) {
        | Some(v) => Some(argon2VersionToJs(v))
        | None => None
        },
      ~salt?,
      ~saltLength?,
      ~associatedData?,
      ~raw=true,
      (),
    );

  hashStringRaw(str, hashOptions);
};

let hashBufferRaw =
    (
      ~hashLength: option(int)=?,
      ~timeCost: option(int)=?,
      ~memoryCost: option(int)=?,
      ~parallelism: option(int)=?,
      ~type_: option(argon2Type)=?,
      ~version: option(argon2Version)=?,
      ~salt: option(Node.Buffer.t)=?,
      ~saltLength: option(int)=?,
      ~associatedData: option(Node.Buffer.t)=?,
      buffer,
    ) => {
  let hashOptions =
    options(
      ~hashLength?,
      ~timeCost?,
      ~memoryCost?,
      ~parallelism?,
      ~type_=?
        switch (type_) {
        | Some(t) => Some(argon2TypeToJs(t))
        | None => None
        },
      ~version=?
        switch (version) {
        | Some(v) => Some(argon2VersionToJs(v))
        | None => None
        },
      ~salt?,
      ~saltLength?,
      ~associatedData?,
      ~raw=true,
      (),
    );

  hashBufferRaw(buffer, hashOptions);
};

let verifyString = (str1, str2) => {
  verifyString(str1, str2);
};

let verifyBuffer = (str, buffer) => {
  verifyBuffer(str, buffer);
};

let needsRehash =
    (
      ~timeCost: option(int)=?,
      ~memoryCost: option(int)=?,
      ~version: option(argon2Version)=?,
      str,
    ) => {
  let hashOptions =
    options(
      ~timeCost?,
      ~memoryCost?,
      ~version=?
        switch (version) {
        | Some(v) => Some(argon2VersionToJs(v))
        | None => None
        },
      ~raw=false,
      (),
    );

  needsRehash(str, hashOptions);
};

let hashToJson = hash => hash |> Js.Json.string;
let jsonToHash = json =>
  json
  |> Js.Json.decodeString
  |> (
    fun
    | Some(hash) => hash
    | None => Js.Exn.raiseError("hash is not a JSON string")
  );
