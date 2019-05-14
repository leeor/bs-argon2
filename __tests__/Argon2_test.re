open Jest;
open Expect;
open Argon2;

type precomputedHashes = {
  argon2i: string,
  withNull: string,
  withAd: string,
  argon2d: string,
  argon2id: string,
  rawArgon2i: Node.Buffer.t,
  rawWithNull: Node.Buffer.t,
  rawArgon2d: Node.Buffer.t,
  rawArgon2id: Node.Buffer.t,
  oldFormat: string,
};

[@bs.val] [@bs.scope "Buffer"]
external allocBuffer: (int, string) => Node.Buffer.t = "alloc";

external toJsExn: Js.Promise.error => Js.Exn.t = "%identity";

let password = "password";
let passwordWithNull = {j|pass\0word|j};
let salt = allocBuffer(16, "salt");
let associatedData = allocBuffer(16, "ad");

let precomputedHashes = {
  argon2i: "$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Iv3dSMJ431p24TEj68Kxokm/ilAC9HfwREDIVPM/1/0",
  withNull: "$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Z3fEValT7xBg6b585WOlY2gufWl95ZfkFA8mPtWJ3UM",
  withAd: "$argon2i$v=19$m=4096,t=3,p=1,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$1VVB4lnD1cmZaeQIlqyOMQ17g6H9rlC5S/vlYOWuD+M",
  argon2d: "$argon2d$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$3CYaDoobFaprD02HTMVVRLsrSgJjZK5QmqYWnWDEAlw",
  argon2id: "$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$fxbFVdPGPQ1NJoy87CaTabyrXOKZepZ9SGBFwPkPJ28",
  rawArgon2i:
    Node.Buffer.fromStringWithEncoding(
      "22fddd48c278df5a76e13123ebc2b1a249bf8a5002f477f04440c854f33fd7fd",
      `hex,
    ),
  rawWithNull:
    Node.Buffer.fromStringWithEncoding(
      "6777c455a953ef1060e9be7ce563a563682e7d697de597e4140f263ed589dd43",
      `hex,
    ),
  rawArgon2d:
    Node.Buffer.fromStringWithEncoding(
      "dc261a0e8a1b15aa6b0f4d874cc55544bb2b4a026364ae509aa6169d60c4025c",
      `hex,
    ),
  rawArgon2id:
    Node.Buffer.fromStringWithEncoding(
      "7f16c555d3c63d0d4d268cbcec269369bcab5ce2997a967d486045c0f90f276f",
      `hex,
    ),
  oldFormat: "$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
};

describe("Argon2", () => {
  test("defaults", () =>
    expect(defaults)
    |> toEqual({
         hashLength: 32,
         saltLength: 16,
         timeCost: 3,
         memoryCost: Int32.shift_left(1l, 12) |> Int32.to_int,
         parallelism: 1,
         type_: Argon2i,
         version: Version13,
       })
  );

  describe("hashString", () => {
    testPromise("with argon2i", () =>
      hashString(~salt, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2i)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2d", () =>
      hashString(~salt, ~type_=Argon2d, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2d)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2id", () =>
      hashString(~salt, ~type_=Argon2id, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2id)
           |> Js.Promise.resolve
         )
    );

    testPromise("with null in password", () =>
      hashString(~salt, passwordWithNull)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.withNull)
           |> Js.Promise.resolve
         )
    );

    testPromise("with associatedData", () =>
      hashString(~associatedData, ~salt, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.withAd)
           |> Js.Promise.resolve
         )
    );
  });

  describe("hashStringRaw", () => {
    testPromise("with argon2i", () =>
      hashStringRaw(~salt, password)
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2i)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2d", () =>
      hashStringRaw(~salt, ~type_=Argon2d, password)
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2d)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2id", () =>
      hashStringRaw(~salt, ~type_=Argon2id, password)
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2id)
           |> Js.Promise.resolve
         )
    );

    testPromise("with null in password", () =>
      hashStringRaw(~salt, passwordWithNull)
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawWithNull)
           |> Js.Promise.resolve
         )
    );
  });

  describe("hashBuffer", () => {
    testPromise("with argon2i", () =>
      hashBuffer(~salt, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2i)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2d", () =>
      hashBuffer(~salt, ~type_=Argon2d, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2d)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2id", () =>
      hashBuffer(~salt, ~type_=Argon2id, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.argon2id)
           |> Js.Promise.resolve
         )
    );

    testPromise("with null in passowrd", () =>
      hashBuffer(~salt, Node.Buffer.fromString(passwordWithNull))
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toEqual(precomputedHashes.withNull)
           |> Js.Promise.resolve
         )
    );
  });

  describe("hashBufferRaw", () => {
    testPromise("with argon2i", () =>
      hashBufferRaw(~salt, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2i)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2d", () =>
      hashBufferRaw(~salt, ~type_=Argon2d, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2d)
           |> Js.Promise.resolve
         )
    );

    testPromise("with argon2id", () =>
      hashBufferRaw(~salt, ~type_=Argon2id, Node.Buffer.fromString(password))
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawArgon2id)
           |> Js.Promise.resolve
         )
    );

    testPromise("with null in password", () =>
      hashBufferRaw(~salt, Node.Buffer.fromString(passwordWithNull))
      |> Js.Promise.then_(hashedBuffer =>
           expect(hashedBuffer)
           |> toEqual(precomputedHashes.rawWithNull)
           |> Js.Promise.resolve
         )
    );
  });

  describe("hashing options", () => {
    testPromise("timeCost", () =>
      hashString(~timeCost=4, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toMatchRe(Js.Re.fromString("t=4"))
           |> Js.Promise.resolve
         )
    );

    testPromise("low timeCost", () => {
      let timeCost = limits.timeCost;

      hashString(~timeCost=timeCost.min - 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re {json|/invalid timeCost.+between \d+ and \d+/i|json}],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("high timeCost", () => {
      let timeCost = limits.timeCost;

      hashString(~timeCost=timeCost.max + 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re {json|/invalid timeCost.+between \d+ and \d+/i|json}],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("hashLength", () =>
      hashString(~hashLength=4, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toMatchRe([%bs.re {json|/\$[^$]{6}$/|json}])
           |> Js.Promise.resolve
         )
    );

    testPromise("low hashLength", () => {
      let hashLength = limits.hashLength;

      hashString(~hashLength=hashLength.min - 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid hashLength.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("high hashLength", () => {
      let hashLength = limits.hashLength;

      hashString(~hashLength=hashLength.max + 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid hashLength.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("memoryCost", () =>
      hashString(
        ~memoryCost=Int32.shift_left(1l, 13) |> Int32.to_int,
        password,
      )
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toMatchRe(Js.Re.fromString("m=8192"))
           |> Js.Promise.resolve
         )
    );

    testPromise("low memoryCost", () => {
      let memoryCost = limits.memoryCost;

      hashString(~memoryCost=memoryCost.min - 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid memoryCost.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("high memoryCost", () => {
      let memoryCost = limits.memoryCost;

      hashString(~memoryCost=memoryCost.max + 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid memoryCost.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("parallelism", () =>
      hashString(~parallelism=2, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toMatchRe(Js.Re.fromString("p=2"))
           |> Js.Promise.resolve
         )
    );

    testPromise("low parallelism", () => {
      let parallelism = limits.parallelism;

      hashString(~parallelism=parallelism.min - 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid parallelism.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("high parallelism", () => {
      let parallelism = limits.parallelism;

      hashString(~parallelism=parallelism.max + 1, password)
      |> Js.Promise.then_(_ =>
           fail("expected hashString to reject") |> Js.Promise.resolve
         )
      |> Js.Promise.catch(exn =>
           expect(exn |> toJsExn |> Js.Exn.message |> Belt.Option.getExn)
           |> toMatchRe(
                [%bs.re
                  {json|/invalid parallelism.+between \d+ and \d+/i|json}
                ],
              )
           |> Js.Promise.resolve
         );
    });

    testPromise("with all options", () =>
      hashString(
        ~timeCost=4,
        ~memoryCost=Int32.shift_left(1l, 13) |> Int32.to_int,
        ~parallelism=2,
        password,
      )
      |> Js.Promise.then_(hashedString =>
           expect(hashedString)
           |> toMatchRe(Js.Re.fromString("m=8192,t=4,p=2"))
           |> Js.Promise.resolve
         )
    );
  });

  describe("needsRehash", () => {
    testPromise("of an old version", () =>
      hashString(~version=Version10, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString |> needsRehash)
           |> toBe(true)
           |> Js.Promise.resolve
         )
    );

    testPromise("of lower memoryCost", () =>
      hashString(~memoryCost=defaults.memoryCost - 1, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString |> needsRehash)
           |> toBe(true)
           |> Js.Promise.resolve
         )
    );

    testPromise("of lower timeCost", () =>
      hashString(~timeCost=2, password)
      |> Js.Promise.then_(hashedString =>
           expect(hashedString |> needsRehash)
           |> toBe(true)
           |> Js.Promise.resolve
         )
    );
  });

  describe("verifyString", () => {
    testPromise("correct password", () =>
      hashString(password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, password)
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(true) |> Js.Promise.resolve
              )
         )
    );

    testPromise("wrong password", () =>
      hashString(password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, "passworld")
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(false) |> Js.Promise.resolve
              )
         )
    );

    testPromise("with null in password", () =>
      hashString(passwordWithNull)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, passwordWithNull)
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(true) |> Js.Promise.resolve
              )
         )
    );

    testPromise("with associatedData", () =>
      hashString(~associatedData, passwordWithNull)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, passwordWithNull)
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(true) |> Js.Promise.resolve
              )
         )
    );

    testPromise("argon2d correct password", () =>
      hashString(~type_=Argon2d, password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, password)
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(true) |> Js.Promise.resolve
              )
         )
    );

    testPromise("argon2d wrong password", () =>
      hashString(~type_=Argon2d, password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, "passworld")
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(false) |> Js.Promise.resolve
              )
         )
    );

    testPromise("argon2id correct password", () =>
      hashString(~type_=Argon2id, password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, password)
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(true) |> Js.Promise.resolve
              )
         )
    );

    testPromise("argon2id wrong password", () =>
      hashString(~type_=Argon2id, password)
      |> Js.Promise.then_(hashedString =>
           verifyString(hashedString, "passworld")
           |> Js.Promise.then_(result =>
                expect(result) |> toBe(false) |> Js.Promise.resolve
              )
         )
    );

    testPromise("old has format", () =>
      verifyString(precomputedHashes.oldFormat, password)
      |> Js.Promise.then_(result =>
           expect(result) |> toBe(true) |> Js.Promise.resolve
         )
    );
  });
});
