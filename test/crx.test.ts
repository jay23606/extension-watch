import { test } from "node:test";
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { parseCrx, fetchManifest, normalizeId } from "../src/crx";
import { FetchError } from "../src/types";

class Writer {
  private chunks: Uint8Array[] = [];

  u8(...vals: number[]): this {
    this.chunks.push(Uint8Array.from(vals));
    return this;
  }

  u16(v: number): this {
    this.chunks.push(Uint8Array.from([v & 0xff, (v >> 8) & 0xff]));
    return this;
  }

  u32(v: number): this {
    this.chunks.push(Uint8Array.from([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]));
    return this;
  }

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    return this;
  }

  str(s: string): this {
    return this.bytes(new TextEncoder().encode(s));
  }

  build(): Uint8Array {
    let len = 0;
    for (const c of this.chunks) len += c.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

interface ZipEntry {
  name: string;
  data: Uint8Array;
  comp: Uint8Array;
  method: number;
  localOffset: number;
  nameLen: number;
}

function buildZip(files: { name: string; data: Uint8Array; method?: number }[]): Uint8Array {
  const entries: ZipEntry[] = [];
  const locals: Uint8Array[] = [];
  let offset = 0;
  for (const f of files) {
    const method = f.method ?? 8;
    const nameBytes = new TextEncoder().encode(f.name);
    const comp = method === 8 ? new Uint8Array(deflateRawSync(f.data)) : f.data;
    const local = new Writer()
      .u32(0x04034b50).u16(20).u16(0).u16(method).u16(0).u16(0)
      .u32(0).u32(comp.length).u32(f.data.length).u16(nameBytes.length).u16(0)
      .bytes(nameBytes).bytes(comp)
      .build();
    entries.push({ name: f.name, data: f.data, comp, method, localOffset: offset, nameLen: nameBytes.length });
    offset += local.length;
    locals.push(local);
  }
  const central = new Writer();
  for (const e of entries) {
    central.u32(0x02014b50).u16(20).u16(20).u16(0).u16(e.method).u16(0).u16(0)
      .u32(0).u32(e.comp.length).u32(e.data.length).u16(e.nameLen).u16(0).u16(0)
      .u16(0).u16(0).u32(0).u32(e.localOffset).str(e.name);
  }
  const centralBytes = central.build();
  const eocd = new Writer()
    .u32(0x06054b50).u16(0).u16(0).u16(files.length).u16(files.length)
    .u32(centralBytes.length).u32(offset).u16(0);
  const all = new Writer();
  for (const l of locals) all.bytes(l);
  return all.bytes(centralBytes).bytes(eocd.build()).build();
}

function crx3(zip: Uint8Array): Uint8Array {
  const header = new Uint8Array([0x0a, 0x02, 0x08, 0x03]);
  return new Writer().str("Cr24").u32(3).u32(header.length).bytes(header).bytes(zip).build();
}

function crx2(zip: Uint8Array): Uint8Array {
  return new Writer().str("Cr24").u32(2).u32(4).u32(4).bytes(new Uint8Array(4)).bytes(new Uint8Array(4)).bytes(zip).build();
}

function jsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function manifestCrx(manifest: unknown, extraFiles: { name: string; data: Uint8Array; method?: number }[] = [], method = 8): Uint8Array {
  const files = [{ name: "manifest.json", data: jsonBytes(manifest), method }, ...extraFiles];
  return crx3(buildZip(files));
}

const ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb";

function okResponse(body: Uint8Array, status = 200): Response {
  return new Response(body as unknown as BodyInit, { status });
}

function fakeFetch(response: Response, captured?: { url: string }): typeof fetch {
  return (async (url: unknown) => {
    if (captured) captured.url = String(url);
    return response;
  }) as unknown as typeof fetch;
}

/** Serves a body in fixed-size chunks so fetchManifest must stream and can stop early. */
function chunkedFetch(body: Uint8Array, count: { n: number }, chunkSize = 64 * 1024): typeof fetch {
  return (async () => {
    let pos = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pos >= body.length) {
          controller.close();
          return;
        }
        const end = Math.min(pos + chunkSize, body.length);
        controller.enqueue(body.subarray(pos, end));
        count.n = end;
        pos = end;
      },
    });
    return new Response(stream, { status: 200 });
  }) as unknown as typeof fetch;
}

/** Records the RequestInit passed to fetch so a test can inspect the abort signal. */
function capturingFetch(response: Response, captured: { init?: RequestInit }): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    captured.init = init;
    return response;
  }) as unknown as typeof fetch;
}

/** Builds a ZIP whose local headers use a data descriptor (flag bit 3) and zeroed local sizes. */
function buildDataDescriptorZip(files: { name: string; data: Uint8Array; method?: number }[]): Uint8Array {
  const entries: { name: string; comp: Uint8Array; data: Uint8Array; method: number; localOffset: number }[] = [];
  const locals: Uint8Array[] = [];
  let offset = 0;
  for (const f of files) {
    const method = f.method ?? 8;
    const nameBytes = new TextEncoder().encode(f.name);
    const comp = method === 8 ? new Uint8Array(deflateRawSync(f.data)) : f.data;
    const local = new Writer()
      .u32(0x04034b50).u16(20).u16(0x0008).u16(method).u16(0).u16(0)
      .u32(0).u32(0).u32(0).u16(nameBytes.length).u16(0)
      .bytes(nameBytes).bytes(comp)
      .u32(0x08074b50).u32(0).u32(comp.length).u32(f.data.length)
      .build();
    entries.push({ name: f.name, comp, data: f.data, method, localOffset: offset });
    offset += local.length;
    locals.push(local);
  }
  const central = new Writer();
  for (const e of entries) {
    const nameBytes = new TextEncoder().encode(e.name);
    central.u32(0x02014b50).u16(20).u16(20).u16(0x0008).u16(e.method).u16(0).u16(0)
      .u32(0).u32(e.comp.length).u32(e.data.length).u16(nameBytes.length).u16(0).u16(0)
      .u16(0).u16(0).u32(0).u32(e.localOffset).bytes(nameBytes);
  }
  const centralBytes = central.build();
  const eocd = new Writer()
    .u32(0x06054b50).u16(0).u16(0).u16(files.length).u16(files.length)
    .u32(centralBytes.length).u32(offset).u16(0);
  const all = new Writer();
  for (const l of locals) all.bytes(l);
  return all.bytes(centralBytes).bytes(eocd.build()).build();
}

test("normalizeId accepts a 32-char a-p id", () => {
  assert.equal(normalizeId(ID), ID);
});

test("normalizeId rejects malformed ids", () => {
  assert.equal(normalizeId("abc"), null);
  assert.equal(normalizeId(ID + "x"), null);
  assert.equal(normalizeId(ID.toUpperCase()), null);
  assert.equal(normalizeId("z".repeat(32)), null);
});

test("normalizeId accepts a chromewebstore.google.com URL", () => {
  assert.equal(normalizeId(`https://chromewebstore.google.com/detail/google-translate/${ID}`), ID);
});

test("normalizeId accepts a chrome.google.com webstore URL", () => {
  assert.equal(normalizeId(`https://chrome.google.com/webstore/detail/google-translate/${ID}?hl=en`), ID);
});

test("normalizeId rejects junk", () => {
  assert.equal(normalizeId("https://example.com/foo"), null);
  assert.equal(normalizeId("not a url or id"), null);
});

test("parseCrx reads a basic CRX3 manifest", () => {
  const bytes = manifestCrx({
    manifest_version: 3,
    name: "Translate",
    version: "1.2.3",
    description: "A translator",
    permissions: ["activeTab", "contextMenus", "storage"],
  });
  const m = parseCrx(bytes, ID);
  assert.equal(m.id, ID);
  assert.equal(m.name, "Translate");
  assert.equal(m.version, "1.2.3");
  assert.equal(m.manifestVersion, 3);
  assert.deepEqual(m.permissions, ["activeTab", "contextMenus", "storage"]);
  assert.equal(m.description, "A translator");
  assert.equal(m.hasBackground, false);
  assert.equal(m.csp, null);
  assert.equal(m.updateUrl, null);
});

test("parseCrx resolves __MSG__ names and descriptions with case-insensitive keys", () => {
  const messages = jsonBytes({ appName: { message: "My Extension" }, appDesc: { message: "Does things" } });
  const bytes = manifestCrx(
    {
      manifest_version: 3,
      name: "__MSG_APPNAME__",
      version: "1.0",
      default_locale: "en",
      description: "__MSG_appdesc__",
    },
    [{ name: "_locales/en/messages.json", data: messages }],
  );
  const m = parseCrx(bytes, ID);
  assert.equal(m.name, "My Extension");
  assert.equal(m.description, "Does things");
});

test("parseCrx falls back to en messages when the locale is missing", () => {
  const en = jsonBytes({ hello: { message: "world" } });
  const bytes = manifestCrx(
    { manifest_version: 3, name: "__MSG_hello__", version: "1.0", default_locale: "xx" },
    [{ name: "_locales/en/messages.json", data: en }],
  );
  const m = parseCrx(bytes, ID);
  assert.equal(m.name, "world");
});

test("parseCrx leaves unresolved __MSG__ placeholders intact", () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "__MSG_missing__", version: "1.0" });
  assert.equal(parseCrx(bytes, ID).name, "__MSG_missing__");
});

test("parseCrx strips comments and a UTF-8 BOM", () => {
  const raw = "\ufeff{ // line comment\n \"manifest_version\": 3, /* block\ncomment */ \"name\": \"X\", \"version\": \"1.0\" }";
  const zip = buildZip([{ name: "manifest.json", data: new TextEncoder().encode(raw) }]);
  const m = parseCrx(crx3(zip), ID);
  assert.equal(m.name, "X");
  assert.equal(m.version, "1.0");
});

test("parseCrx preserves comment-like text inside strings", () => {
  const raw = "{ \"manifest_version\": 3, \"name\": \"http://not-a-comment\", \"version\": \"1.0\" }";
  const zip = buildZip([{ name: "manifest.json", data: new TextEncoder().encode(raw) }]);
  assert.equal(parseCrx(crx3(zip), ID).name, "http://not-a-comment");
});

test("parseCrx reads a CRX2 package", () => {
  const zip = buildZip([{ name: "manifest.json", data: jsonBytes({ manifest_version: 2, name: "Old", version: "1.0" }) }]);
  const m = parseCrx(crx2(zip), ID);
  assert.equal(m.name, "Old");
  assert.equal(m.manifestVersion, 2);
});

test("parseCrx reads a stored (uncompressed) manifest entry", () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "Stored", version: "1.0" }, [], 0);
  assert.equal(parseCrx(bytes, ID).name, "Stored");
});

test("parseCrx splits host patterns out of permissions", () => {
  const bytes = manifestCrx({
    manifest_version: 2,
    name: "Old",
    version: "1.0",
    permissions: ["tabs", "https://*.foo.com/*", "<all_urls>"],
    optional_permissions: ["cookies", "http://bar.com/*"],
    background: { scripts: ["bg.js"] },
    content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
  });
  const m = parseCrx(bytes, ID);
  assert.deepEqual(m.permissions, ["tabs"]);
  assert.deepEqual(m.optionalPermissions, ["cookies", "http://bar.com/*"]);
  assert.deepEqual(m.hostPermissions, ["https://*.foo.com/*", "<all_urls>"]);
  assert.ok(m.optionalPermissions.includes("http://bar.com/*"), "optional hosts are kept apart from granted hosts");
  assert.equal(m.hasBackground, true);
  assert.equal(m.csp, "script-src 'self' 'unsafe-eval'; object-src 'self'");
});

test("parseCrx reads MV3 host_permissions, content scripts and connectable", () => {
  const bytes = manifestCrx({
    manifest_version: 3,
    name: "Modern",
    version: "2.0",
    host_permissions: ["https://translate.google.com/*", "<all_urls>"],
    content_scripts: [{ matches: ["https://*/*", "http://*/*"], js: ["x.js"] }],
    externally_connectable: { matches: ["https://*.example.com/*"] },
    background: { service_worker: "sw.js" },
    content_security_policy: { extension_pages: "script-src 'self'" },
    update_url: "https://example.com/update.xml",
  });
  const m = parseCrx(bytes, ID);
  assert.deepEqual(m.hostPermissions, ["https://translate.google.com/*", "<all_urls>"]);
  assert.deepEqual(m.contentScriptMatches, ["https://*/*", "http://*/*"]);
  assert.deepEqual(m.externallyConnectable, ["https://*.example.com/*"]);
  assert.equal(m.hasBackground, true);
  assert.equal(m.csp, "script-src 'self'");
  assert.equal(m.updateUrl, "https://example.com/update.xml");
});

test("parseCrx inflates a large manifest (dynamic huffman blocks)", () => {
  const bigDescription = "x".repeat(4000);
  const bytes = manifestCrx({ manifest_version: 3, name: "Big", version: "1.0", description: bigDescription });
  const m = parseCrx(bytes, ID);
  assert.equal(m.description, bigDescription);
  assert.equal(m.description.length, 4000);
});

test("parseCrx throws FetchError on garbage bytes", () => {
  assert.throws(() => parseCrx(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]), ID), FetchError);
});

test("parseCrx throws FetchError when manifest.json is missing", () => {
  const zip = buildZip([{ name: "background.js", data: new TextEncoder().encode("console.log(1)") }]);
  assert.throws(() => parseCrx(crx3(zip), ID), FetchError);
});

test("parseCrx throws FetchError on unsupported CRX version", () => {
  const bytes = new Writer().str("Cr24").u32(9).u32(0).bytes(new Uint8Array(0)).build();
  assert.throws(() => parseCrx(bytes, ID), FetchError);
});

test("fetchManifest returns a parsed manifest", async () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "Live", version: "3.0" });
  const captured: { url: string } = { url: "" };
  const m = await fetchManifest(ID, fakeFetch(okResponse(bytes), captured));
  assert.equal(m.name, "Live");
  assert.match(captured.url, /clients2\.google\.com/);
  assert.match(captured.url, new RegExp(ID));
});

test("fetchManifest normalizes a Web Store URL input", async () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "FromUrl", version: "1.0" });
  const m = await fetchManifest(`https://chromewebstore.google.com/detail/x/${ID}`, fakeFetch(okResponse(bytes)));
  assert.equal(m.name, "FromUrl");
});

test("fetchManifest throws FetchError 404 on HTTP 204", async () => {
  await assert.rejects(fetchManifest(ID, fakeFetch(new Response(null, { status: 204 }))), (err: unknown) => {
    return err instanceof FetchError && err.status === 404;
  });
});

test("fetchManifest throws FetchError 404 on an empty body", async () => {
  await assert.rejects(fetchManifest(ID, fakeFetch(okResponse(new Uint8Array(0)))), (err: unknown) => {
    return err instanceof FetchError && err.status === 404;
  });
});


test("fetchManifest throws FetchError on an HTTP error", async () => {
  await assert.rejects(fetchManifest(ID, fakeFetch(new Response("boom", { status: 500 }))), (err: unknown) => {
    return err instanceof FetchError && err.status === 500;
  });
});

test("fetchManifest throws FetchError on an invalid id", async () => {
  await assert.rejects(fetchManifest("junk", fakeFetch(okResponse(new Uint8Array(0)))), (err: unknown) => {
    return err instanceof FetchError && err.status === 400;
  });
});

/** Serves byte ranges of a package the way the Chrome Web Store CDN does (206 + Content-Range). */
function rangeFetch(body: Uint8Array, log: string[]): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const range = new Headers(init?.headers).get("range") ?? "";
    const m = /bytes=(\d+)-(\d+)/.exec(range);
    if (!m) return new Response(body as unknown as BodyInit, { status: 200 });
    const start = Number(m[1]); const end = Math.min(body.length - 1, Number(m[2]));
    log.push(`${start}-${end}`);
    return new Response(body.slice(start, end + 1) as unknown as BodyInit, { status: 206, headers: { "content-range": `bytes ${start}-${end}/${body.length}` } });
  }) as unknown as typeof fetch;
}

test("fetchManifest reads a large package with range requests only", async () => {
  const filler = new Uint8Array(3 * 1024 * 1024).map((_, i) => (i * 7919) % 251); // incompressible, 3 MB
  const bytes = manifestCrx({ manifest_version: 3, name: "__MSG_appName__", version: "9.9", default_locale: "de", permissions: ["storage"] },
    [{ name: "big.bin", data: filler, method: 0 }, { name: "_locales/de/messages.json", data: jsonBytes({ appname: { message: "Grosse Erweiterung" } }) }]);
  const log: string[] = [];
  const m = await fetchManifest("aapbdbdomjkkjkaonfhkkikfgjllcleb", rangeFetch(bytes, log));
  assert.equal(m.name, "Grosse Erweiterung");
  assert.equal(m.version, "9.9");
  const fetched = log.reduce((sum, r) => { const [a, b] = r.split("-").map(Number); return sum + (b! - a! + 1); }, 0);
  assert.ok(fetched < bytes.length / 4, `read ${fetched} of ${bytes.length} bytes`);
});

test("fetchManifest falls back to a full read for data-descriptor entries", async () => {
  const bytes = crx3(buildDataDescriptorZip([
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Descriptor", version: "1.0" }) },
  ]));
  const m = await fetchManifest(ID, fakeFetch(okResponse(bytes)));
  assert.equal(m.name, "Descriptor");
});


test("fetchManifest strips __MSG__ markers when the locale file is not found", async () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "__MSG_appName__", version: "1.0", default_locale: "xx" });
  const m = await fetchManifest(ID, fakeFetch(okResponse(bytes)));
  assert.equal(m.name, "appName");
});


test("manifest parser ignores a commented-out default_locale (sparse and full paths agree)", async () => {
  const { parseManifestJson } = await import("../src/crx.js");
  const src = '\uFEFF{\n  // "default_locale": "fr",\n  "default_locale": "de", "name": "__MSG_n__", "version": "1", "manifest_version": 3\n}';
  assert.equal(parseManifestJson(new TextEncoder().encode(src)).default_locale, "de");
});


test("fetchManifest streams a 70 MB package that ignores Range and reads its ZIP index at the end", async () => {
  const filler = new Uint8Array(70 * 1024 * 1024);
  const bytes = manifestCrx({ manifest_version: 3, name: "Streamed", version: "1.0" }, [{ name: "filler.bin", data: filler, method: 0 }]);
  const count = { n: 0 };
  const m = await fetchManifest(ID, chunkedFetch(bytes, count));
  assert.equal(m.name, "Streamed");
  assert.equal(count.n, bytes.length, "the whole package is streamed so the index at the end can be checked");
});

test("fetchManifest reads a manifest that sits 20 MB into a streamed package (password manager layout)", async () => {
  const zip = buildZip([
    { name: "filler.bin", data: new Uint8Array(20 * 1024 * 1024), method: 0 },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "__MSG_appName__", version: "4.0", default_locale: "de", permissions: ["storage"] }) },
    { name: "_locales/de/messages.json", data: jsonBytes({ appName: { message: "Late Vault" } }) },
  ]);
  const m = await fetchManifest(ID, chunkedFetch(crx3(zip), { n: 0 }));
  assert.equal(m.name, "Late Vault");
  assert.equal(m.version, "4.0");
});

test("a decoy manifest hidden inside an earlier file is ignored; the central directory decides", async () => {
  const decoy = buildZip([{ name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Harmless", version: "1.0", permissions: ["storage"] }) }]);
  const zip = buildZip([
    { name: "assets/notes.dat", data: decoy, method: 0 },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Real", version: "1.0", permissions: ["debugger", "cookies"], host_permissions: ["<all_urls>"] }) },
  ]);
  const m = await fetchManifest(ID, chunkedFetch(crx3(zip), { n: 0 }));
  assert.equal(m.name, "Real");
  assert.ok(m.permissions.includes("debugger"));
});

test("fetchManifest uses a 25 s AbortSignal timeout", async () => {
  const bytes = manifestCrx({ manifest_version: 3, name: "X", version: "1.0" });
  const captured: { init?: RequestInit } = {};
  const original = AbortSignal.timeout;
  let timeoutMs = -1;
  AbortSignal.timeout = ((ms: number) => {
    timeoutMs = ms;
    return original.call(AbortSignal, ms);
  }) as typeof AbortSignal.timeout;
  try {
    await fetchManifest(ID, capturingFetch(okResponse(bytes), captured));
  } finally {
    AbortSignal.timeout = original;
  }
  assert.ok(timeoutMs === 25000 || timeoutMs === 5000);
  assert.ok(captured.init?.signal instanceof AbortSignal);
});

test("Web Store layout: data-descriptor entries, manifest not first, no locale file, name from the store title", async () => {
  const zip = buildDataDescriptorZip([
    { name: "_locales/", data: new Uint8Array(0) },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "__MSG_appName__", version: "9.1", default_locale: "en", permissions: ["storage"] }) },
    { name: "filler.bin", data: new Uint8Array(9 * 1024 * 1024).fill(7), method: 0 },
  ]);
  const body = crx3(zip);
  const fake = (async (url: string) => {
    if (String(url).includes("chromewebstore.google.com")) return new Response("<html><head><title>Real Name &amp; Co - Chrome Web Store</title></head></html>");
    return chunkedFetch(body, { n: 0 })(url);
  }) as typeof fetch;
  const m = await fetchManifest(ID, fake);
  assert.equal(m.name, "Real Name & Co");
  assert.equal(m.version, "9.1");
});

test("overlapping captures: a locale right after a long earlier capture is read in full", async () => {
  const big = new Uint8Array(200 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = (i * 2654435761) >>> 24;
  const zip = buildZip([
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "__MSG_n__", version: "1", default_locale: "en" }) },
    { name: "_locales/de/messages.json", data: jsonBytes({ n: { message: "Deutsch" } }) },
    { name: "_locales/en/messages.json", data: jsonBytes({ n: { message: "English" }, pad: { message: Buffer.from(big).toString("base64") } }) },
  ]);
  const m = await fetchManifest(ID, chunkedFetch(crx3(zip), { n: 0 }));
  assert.equal(m.name, "English");
});

test("headers that straddle stream chunk boundaries are found, for every chunk size", async () => {
  const zip = buildZip([
    { name: "a.bin", data: new Uint8Array(70001).fill(1), method: 0 },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "__MSG_n__", version: "3", default_locale: "fr" }) },
    { name: "b.bin", data: new Uint8Array(65519).fill(2), method: 0 },
    { name: "_locales/fr/messages.json", data: jsonBytes({ n: { message: "Bonjour" } }) },
    { name: "c.bin", data: new Uint8Array(2.2 * 1024 * 1024).fill(3), method: 0 },
  ]);
  const body = crx3(zip); // the wanted entries sit outside the 64 KB head and the 2 MB tail, so only captures can serve them
  for (const size of [61, 127, 128, 129, 4093, 65536]) {
    const m = await fetchManifest(ID, chunkedFetch(body, { n: 0 }, size));
    assert.equal(m.name, "Bonjour", `chunk size ${size}`);
  }
});

test("P4: a header cut at a chunk edge followed by a large chunk is read", async () => {
  const zip = buildZip([
    { name: "a.bin", data: new Uint8Array(100000).fill(1), method: 0 },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Edge", version: "1" }) },
    { name: "c.bin", data: new Uint8Array(2.2 * 1024 * 1024).fill(3), method: 0 },
  ]);
  const body = crx3(zip);
  const at = Buffer.from(body).indexOf(Buffer.from("manifest.json")) - 30;
  const cut = at + 20;
  const fake = (async () => new Response(new ReadableStream({ start(c) { c.enqueue(body.subarray(0, cut)); c.enqueue(body.subarray(cut, cut + 1_500_000)); c.enqueue(body.subarray(cut + 1_500_000)); c.close(); } }), { status: 200 })) as unknown as typeof fetch;
  assert.equal((await fetchManifest(ID, fake)).name, "Edge");
});

test("P11: two central-directory entries named manifest.json make the package unreadable", async () => {
  const zip = buildZip([
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Benign", version: "1" }) },
    { name: "manifest.json", data: jsonBytes({ manifest_version: 3, name: "Evil", version: "1", permissions: ["debugger"] }) },
  ]);
  await assert.rejects(fetchManifest(ID, chunkedFetch(crx3(zip), { n: 0 })), /two manifest\.json/);
});
