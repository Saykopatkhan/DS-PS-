import { copyFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
const root = new URL("../", import.meta.url);
const output = new URL("web/static/vendor/", root);
await mkdir(output, { recursive: true });
for (const [source, target] of [
  ["lenis/dist/lenis.min.js", "lenis.min.js"],
  ["lenis/dist/lenis.css", "lenis.css"],
  ["lenis/LICENSE", "LENIS-LICENSE.txt"],
  ["animejs/dist/bundles/anime.umd.min.js", "anime.umd.min.js"],
  ["animejs/LICENSE.md", "ANIME-LICENSE.txt"],
]) {
  await copyFile(
    new URL(`node_modules/${source}`, root),
    new URL(target, output),
  );
}
console.log(`Pinned frontend assets copied to ${fileURLToPath(output)}`);
