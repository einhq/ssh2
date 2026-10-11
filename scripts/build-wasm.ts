/**
 * Assembles src/crypto/chachapoly.wat into src/crypto/chachapoly-wasm.ts, the
 * module's bytes as base64. Run with `deno task build:wasm` after editing the
 * .wat; test/chachapoly_wasm_test.ts fails while the two disagree.
 */

import wabtInit from 'wabt';

const WAT = new URL('../src/crypto/chachapoly.wat', import.meta.url);
const OUT = new URL('../src/crypto/chachapoly-wasm.ts', import.meta.url);

/** The generated TypeScript source for the .wat at WAT. */
export async function generate(): Promise<string> {
  const wabt = await wabtInit();
  const module = wabt.parseWat('chachapoly.wat', await Deno.readTextFile(WAT));
  module.validate();
  const { buffer } = module.toBinary({ write_debug_names: false });
  module.destroy();

  let binary = '';
  for (const byte of buffer) binary += String.fromCharCode(byte);
  const lines = btoa(binary).match(/.{1,92}/g)!.map((line) => `  '${line}'`).join(' +\n');

  return `// Generated from chachapoly.wat by \`deno task build:wasm\`. Do not edit.

const BASE64 =
${lines};

/** The WebAssembly module assembled from chachapoly.wat. */
export const CHACHAPOLY_WASM: Uint8Array = Uint8Array.from(atob(BASE64), (c) => c.charCodeAt(0));
`;
}

if (import.meta.main) {
  await Deno.writeTextFile(OUT, await generate());
}
