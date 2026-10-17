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

test("fetchManifest throws FetchError 413 on an oversize package", async () => {
  const big = new Response(new Uint8Array(60 * 1024 * 1024 + 1) as unknown as BodyInit);
  await assert.rejects(fetchManifest(ID, fakeFetch(big)), (err: unknown) => {
    return err instanceof FetchError && err.status === 413;
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
