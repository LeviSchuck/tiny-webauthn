// ex. scripts/build_npm.ts
import { build, emptyDir } from "@deno/dnt";

await emptyDir("./npm");

const lockFile = JSON.parse(await Deno.readTextFile("./deno.lock"));

function findHighestVersion(pattern: string): string | null {
  const regex = new RegExp(pattern.replace(/\*/g, ".*"));
  let highestVersion: string | null = null;

  for (const [key, version] of Object.entries(lockFile.specifiers)) {
    if (regex.test(key) && typeof version === "string") {
      if (
        highestVersion === null || compareVersions(version, highestVersion) > 0
      ) {
        highestVersion = version;
      }
    }
  }

  return highestVersion;
}

function compareVersions(a: string, b: string): number {
  const aParts = a.split(".").map(Number);
  const bParts = b.split(".").map(Number);

  for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
    const aPart = aParts[i] || 0;
    const bPart = bParts[i] || 0;

    if (aPart > bPart) return 1;
    if (aPart < bPart) return -1;
  }

  return 0;
}

const tinyCborVersion = findHighestVersion("jsr:@levischuck/tiny-cbor@*");
const tinyCoseVersion = findHighestVersion("jsr:@levischuck/tiny-cose@*");
const tinyEncodingsVersion = findHighestVersion(
  "jsr:@levischuck/tiny-encodings@*",
);

if (!tinyCborVersion || !tinyCoseVersion || !tinyEncodingsVersion) {
  throw new Error(
    `Failed to get version from deno.lock: ${tinyCborVersion} ${tinyCoseVersion} ${tinyEncodingsVersion}`,
  );
}

await build({
  entryPoints: ["./index.ts"],
  outDir: "./npm",
  shims: {
    deno: true,
  },
  test: false,
  // Deno to node doesn't support mapping JSR to NPM for some reason :/
  // mappings: {
  //   ["jsr:@levischuck/tiny-cbor"]: {
  //     name: "@levischuck/tiny-cbor",
  //     version: tinyCborVersion,
  //   },
  //   ["jsr:@levischuck/tiny-cose"]: {
  //     name: "@levischuck/tiny-cose",
  //     version: tinyCoseVersion,
  //   },
  //   ["jsr:@levischuck/tiny-encodings"]: {
  //     name: "@levischuck/tiny-encodings",
  //     version: tinyEncodingsVersion,
  //   },
  // },
  package: {
    // package.json properties
    name: "@levischuck/tiny-webauthn",
    version: Deno.args[0],
    description:
      "Tiny WebAuthn library to register and authenticate security keys and passkeys",
    license: "MIT",
    repository: {
      type: "git",
      url: "https://github.com/LeviSchuck/tiny-webauthn",
    },
    bugs: {
      url: "https://github.com/levischuck/tiny-webauthn/issues",
    },
    types: "./esm/index.d.ts",
    exports: {
      ".": {
        types: "./esm/index.d.ts",
        import: "./esm/index.js",
        require: "./script/index.js",
      },
    },
  },
  compilerOptions: {
    lib: ["ES2021", "DOM"],
  },
  postBuild() {
    // steps to run after building and before running the tests
    Deno.copyFileSync("LICENSE.txt", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");

    const packageJson = JSON.parse(Deno.readTextFileSync("npm/package.json"));
    const dependencies = packageJson.dependencies || {};
    packageJson.dependencies = dependencies;
    dependencies["@levischuck/tiny-cbor"] = tinyCborVersion;
    dependencies["@levischuck/tiny-cose"] = tinyCoseVersion;
    dependencies["@levischuck/tiny-encodings"] = tinyEncodingsVersion;
    Deno.writeTextFileSync(
      "npm/package.json",
      JSON.stringify(packageJson, null, 2),
    );

    const proc = new Deno.Command("npm", { args: ["install"], cwd: "npm" })
      .outputSync();
    if (proc.code !== 0) {
      throw new Error(`Failed to run npm install: ${proc.code}`);
    }

    function removeIfExists(path: string): void {
      try {
        Deno.removeSync(path, { recursive: true });
      } catch (_error) {
        return;
      }
    }

    for (
      const packageName of [
        "tiny-cbor",
        "tiny-cose",
        "tiny-encodings",
      ]
    ) {
      removeIfExists(`npm/esm/deps/jsr.io/@levischuck/${packageName}`);
      removeIfExists(`npm/script/deps/jsr.io/@levischuck/${packageName}`);
      removeIfExists(`npm/src/deps/jsr.io/@levischuck/${packageName}`);
    }

    function listFilesRecursive(dir: string): string[] {
      const files: string[] = [];
      const entries = Deno.readDirSync(dir);

      for (const entry of entries) {
        const fullPath = `${dir}/${entry.name}`;
        if (entry.isDirectory) {
          files.push(...listFilesRecursive(fullPath));
        } else {
          files.push(fullPath);
        }
      }

      return files;
    }

    const esmFiles = listFilesRecursive("npm/esm");
    const scriptFiles = listFilesRecursive("npm/script");
    const srcFiles = listFilesRecursive("npm/src");
    const allFiles = [...esmFiles, ...scriptFiles, ...srcFiles];
    const jsFiles = allFiles.filter((file) =>
      file.endsWith(".js") || file.endsWith(".d.ts") || file.endsWith(".ts")
    );

    for (const file of jsFiles) {
      const content = Deno.readTextFileSync(file);
      let updatedContent = content.replace(
        /(\.\.\/)+deps\/jsr\.io\/@levischuck\/tiny-cbor\/[^\/]+\/index\.js/g,
        "@levischuck/tiny-cbor",
      );
      updatedContent = updatedContent.replace(
        /(\.\.\/)+deps\/jsr\.io\/@levischuck\/tiny-cose\/[^\/]+\/index\.js/g,
        "@levischuck/tiny-cose",
      );
      updatedContent = updatedContent.replace(
        /(\.\.\/)+deps\/jsr\.io\/@levischuck\/tiny-encodings\/[^\/]+\/index\.js/g,
        "@levischuck/tiny-encodings",
      );
      if (updatedContent !== content) {
        Deno.writeTextFileSync(file, updatedContent);
      }
    }

    for (const file of jsFiles) {
      const content = Deno.readTextFileSync(file);
      if (content.includes("deps/jsr.io/@levischuck")) {
        throw new Error(`Found inlined JSR dependency reference in ${file}`);
      }
    }

    function removeEmptyDirsRecursive(dir: string): void {
      try {
        const entries = Array.from(Deno.readDirSync(dir));
        for (const entry of entries) {
          if (entry.isDirectory) {
            removeEmptyDirsRecursive(`${dir}/${entry.name}`);
          }
        }

        if (Array.from(Deno.readDirSync(dir)).length === 0) {
          Deno.removeSync(dir);
        }
      } catch (_error) {
        return;
      }
    }

    removeEmptyDirsRecursive("npm/esm/deps");
    removeEmptyDirsRecursive("npm/script/deps");
    removeEmptyDirsRecursive("npm/src/deps");

    for (const file of srcFiles) {
      if (!file.endsWith(".ts")) {
        continue;
      }
      const content = Deno.readTextFileSync(file);
      const updatedContent = content.replace(/\.js('|")/g, ".ts$1");
      Deno.writeTextFileSync(file, updatedContent);
    }
  },
});
