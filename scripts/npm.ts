// ex. scripts/build_npm.ts
import { build, emptyDir } from "https://deno.land/x/dnt@0.37.0/mod.ts";

await emptyDir("./npm");

await build({
  entryPoints: ["./index.ts"],
  outDir: "./npm",
  shims: {
    deno: true,
  },
  test: false,
  mappings: {
    "https://deno.land/x/tiny_encodings@0.2.1/index.ts": {
      name: "@levischuck/tiny-encodings",
      version: "0.2.1",
    },
    "https://deno.land/x/tiny_cbor@0.2.2/index.ts": {
      name: "@levischuck/tiny-cbor",
      version: "0.2.2",
    },
    "https://deno.land/x/tiny_cose@0.0.9/index.ts": {
      name: "@levischuck/tiny-cose",
      version: "0.0.9",
    },
  },
  package: {
    // package.json properties
    name: "@levischuck/tiny-webauthn",
    version: Deno.args[0],
    description:
      "Tiny WebAuthn library to register and authenticate security keys and passkeys",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/levischuck/tiny-webauthn.git",
    },
    bugs: {
      url: "https://github.com/levischuck/tiny-webauthn/issues",
    },
  },
  compilerOptions: {
    lib: ["ES2021", "DOM"],
  },
  postBuild() {
    // steps to run after building and before running the tests
    Deno.copyFileSync("LICENSE.txt", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});
