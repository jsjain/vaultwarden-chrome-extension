import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import * as esbuild from "esbuild";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const artifacts = path.join(root, "artifacts");
const watch = process.argv.includes("--watch");

if (path.basename(dist) !== "dist" || path.dirname(dist) !== root) {
  throw new Error(`Refusing to clean unexpected output path: ${dist}`);
}

await rm(dist, { recursive: true, force: true });
await mkdir(path.join(dist, "popup"), { recursive: true });
await mkdir(path.join(dist, "offscreen"), { recursive: true });
await mkdir(path.join(dist, "icons"), { recursive: true });
await mkdir(artifacts, { recursive: true });

await Promise.all([
  cp(path.join(root, "src/manifest.json"), path.join(dist, "manifest.json")),
  cp(path.join(root, "src/popup/index.html"), path.join(dist, "popup/index.html")),
  cp(path.join(root, "src/popup/styles.css"), path.join(dist, "popup/styles.css")),
  cp(path.join(root, "src/offscreen/index.html"), path.join(dist, "offscreen/index.html")),
  cp(path.join(root, "src/icons"), path.join(dist, "icons"), { recursive: true }),
]);

const common = {
  bundle: true,
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  target: "chrome120",
  logLevel: "info",
  legalComments: "none",
  metafile: true,
};

const builds = [
  {
    name: "background",
    options: {
      ...common,
      entryPoints: [path.join(root, "src/background/index.ts")],
      outfile: path.join(dist, "background.js"),
      format: "esm",
    },
  },
  {
    name: "popup",
    options: {
      ...common,
      entryPoints: [path.join(root, "src/popup/index.ts")],
      outfile: path.join(dist, "popup/index.js"),
      format: "esm",
    },
  },
  {
    name: "offscreen",
    options: {
      ...common,
      entryPoints: [path.join(root, "src/offscreen/index.ts")],
      outfile: path.join(dist, "offscreen/index.js"),
      format: "esm",
    },
  },
  {
    name: "site",
    options: {
      ...common,
      entryPoints: [path.join(root, "src/site/index.ts")],
      outfile: path.join(dist, "site.js"),
      format: "iife",
    },
  },
];

if (watch) {
  const contexts = [];
  for (const build of builds) {
    const context = await esbuild.context(build.options);
    await context.watch();
    contexts.push(context);
  }
  console.log("Watching extension sources. Press Ctrl+C to stop.");
} else {
  for (const build of builds) {
    const result = await esbuild.build(build.options);
    await writeFile(
      path.join(artifacts, `${build.name}-metafile.json`),
      JSON.stringify(result.metafile, null, 2),
    );
  }

  const manifest = JSON.parse(await readFile(path.join(dist, "manifest.json"), "utf8"));
  console.log(`Built ${manifest.name} ${manifest.version} in ${path.relative(root, dist)}/`);
}
