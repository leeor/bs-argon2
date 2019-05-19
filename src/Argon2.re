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

let decodeDefaultsValue = (key, decoder, json) => {
  Js.Dict.get(json, key) |> decoder;
};

let decodeIntValue = (fallback, possibleJson) =>
  switch (possibleJson) {
  | Some(json) =>
    json
    |> Js.Json.decodeNumber
    |> (
      fun
      | Some(num) => num |> int_of_float
      | None => fallback
    )
  | None => fallback
  };

let decodeType = possibleJson => {
  switch (possibleJson) {
  | Some(json) =>
    json
    |> Js.Json.decodeNumber
    |> (
      fun
      | Some(0.) => Argon2d
      | Some(1.) => Argon2i
      | Some(2.) => Argon2id
      | _ =>
        Js.Exn.raiseError("unknown Argon2 type: " ++ Js.Json.stringify(json))
    )
  | None =>
    Js.Exn.raiseError("Argon2 type information not found in defaults object")
  };
};

let decodeVersion = possibleJson => {
  switch (possibleJson) {
  | Some(json) =>
    json
    |> Js.Json.decodeNumber
    |> (
      fun
      | Some(16.) => Version10
      | Some(19.) => Version13
      | _ =>
        Js.Exn.raiseError(
          "unknown Argon2 version: " ++ Js.Json.stringify(json),
        )
    )
  | _ => Js.Exn.raiseError("version information not found in defaults object")
  };
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

let decodeNumericLimits = (key, json) => {
  let possibleLimits =
    switch (Js.Dict.get(json, key)) {
    | Some(obj) => obj |> Js.Json.decodeObject
    | None => None
    };

  let limits =
    possibleLimits |> Belt.Option.getWithDefault(_, Js.Dict.empty());

  {
    min:
      limits
      |> Js.Dict.get(_, "min")
      |> (
        num =>
          switch (num) {
          | Some(num) => num |> Js.Json.decodeNumber
          | None => None
          }
      )
      |> Belt.Option.getWithDefault(_, 0.)
      |> int_of_float,
    max:
      limits
      |> Js.Dict.get(_, "max")
      |> (
        num =>
          switch (num) {
          | Some(num) => num |> Js.Json.decodeNumber
          | None => None
          }
      )
      |> Belt.Option.getWithDefault(_, Int32.max_int |> Int32.to_float)
      |> int_of_float,
  };
};

[@bs.module "argon2"] external limits_: Js.Json.t = "limits";

let decodedLimits =
  limits_
  |> Js.Json.decodeObject
  |> Belt.Option.getWithDefault(_, Js.Dict.empty());

let limits = {
  hashLength: decodedLimits |> decodeNumericLimits("hashLength"),
  timeCost: decodedLimits |> decodeNumericLimits("timeCost"),
  memoryCost: decodedLimits |> decodeNumericLimits("memoryCost"),
  parallelism: decodedLimits |> decodeNumericLimits("parallelism"),
};

[@bs.module "argon2"] external defaults_: Js.Json.t = "defaults";

let decodedDefaults =
  defaults_
  |> Js.Json.decodeObject
  |> Belt.Option.getWithDefault(_, Js.Dict.empty());

let defaults = {
  hashLength:
    decodedDefaults |> decodeDefaultsValue("hashLength", decodeIntValue(0)),
  timeCost:
    decodedDefaults |> decodeDefaultsValue("timeCost", decodeIntValue(0)),
  memoryCost:
    decodedDefaults |> decodeDefaultsValue("memoryCost", decodeIntValue(0)),
  parallelism:
    decodedDefaults |> decodeDefaultsValue("parallelism", decodeIntValue(0)),
  type_: decodedDefaults |> decodeDefaultsValue("type", decodeType),
  version: decodedDefaults |> decodeDefaultsValue("version", decodeVersion),
  saltLength:
    decodedDefaults |> decodeDefaultsValue("saltLength", decodeIntValue(0)),
};

[@bs.module "argon2"]
external hashString: (string, options) => Js.Promise.t(argon2Hash) = "hash";

[@bs.module "argon2"]
external hashBuffer: (Node.Buffer.t, options) => Js.Promise.t(argon2Hash) =
  "hash";

[@bs.module "argon2"]
external hashStringRaw: (string, options) => Js.Promise.t(Node.Buffer.t) =
  "hash";

[@bs.module "argon2"]
external hashBufferRaw:
  (Node.Buffer.t, options) => Js.Promise.t(Node.Buffer.t) =
  "hash";

[@bs.module "argon2"]
external verifyString: (argon2Hash, string) => Js.Promise.t(bool) = "verify";

[@bs.module "argon2"]
external verifyBuffer: (argon2Hash, Node.Buffer.t) => Js.Promise.t(bool) =
  "verify";

[@bs.module "argon2"] external needsRehash: (argon2Hash, options) => bool = "";

type hashInput =
  | String(string)
  | Buffer(Node.Buffer.t);

let hash =
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
      input,
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

  let hashPromise =
    switch (input) {
    | String(str) => hashString(str, hashOptions)
    | Buffer(buf) => hashBuffer(buf, hashOptions)
    };

  hashPromise;
};

let hashRaw =
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
      input,
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

  let hashPromise =
    switch (input) {
    | String(str) => hashStringRaw(str, hashOptions)
    | Buffer(buf) => hashBufferRaw(buf, hashOptions)
    };

  hashPromise;
};

let verify = (hash, input) =>
  switch (input) {
  | String(str) => verifyString(hash, str)
  | Buffer(buf) => verifyBuffer(hash, buf)
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
