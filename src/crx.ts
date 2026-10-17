import { FetchError, type Manifest } from "./types";

const DOWNLOAD_TIMEOUT_MS = 8000;
const MAX_CRX_BYTES = 60 * 1024 * 1024;
const STREAM_LIMIT = 40 * 1024 * 1024;
const MAXBITS = 15;

const LENGTH_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

interface Huffman {
  count: number[];
  symbol: number[];
}

const decoder = new TextDecoder("utf-8");
const encoder = new TextEncoder();

export function normalizeId(input: string): string | null {
  const value = input.trim();
  if (/^[a-p]{32}$/.test(value)) return value;
  return idFromUrl(value);
}

function idFromUrl(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.hostname !== "chromewebstore.google.com" && url.hostname !== "chrome.google.com") {
    return null;
  }
  for (const part of url.pathname.split("/")) {
    if (/^[a-p]{32}$/.test(part)) return part;
  }
  return null;
}

function u16le(bytes: Uint8Array, off: number): number {
  return (bytes[off]! | (bytes[off + 1]! << 8)) >>> 0;
}

function u32le(bytes: Uint8Array, off: number): number {
  return (bytes[off]! | (bytes[off + 1]! << 8) | (bytes[off + 2]! << 16) | (bytes[off + 3]! << 24)) >>> 0;
}

function decodeUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

function buildHuffman(lengths: number[]): Huffman {
  const count = new Array<number>(MAXBITS + 1).fill(0);
  for (const len of lengths) {
    if (len > 0 && len <= MAXBITS) count[len] = count[len]! + 1;
  }
  const symbol: number[] = [];
  const offset = new Array<number>(MAXBITS + 1).fill(0);
  for (let len = 1; len < MAXBITS; len++) {
    offset[len + 1] = offset[len]! + count[len]!;
  }
  lengths.forEach((len, s) => {
    if (len > 0 && len <= MAXBITS) {
      symbol[offset[len]!] = s;
      offset[len] = offset[len]! + 1;
    }
  });
  return { count, symbol };
}

function fixedLiteralLengths(): number[] {
  const lengths = new Array<number>(288);
  for (let i = 0; i < 288; i++) {
    if (i < 144) lengths[i] = 8;
    else if (i < 256) lengths[i] = 9;
    else if (i < 280) lengths[i] = 7;
    else lengths[i] = 8;
  }
  return lengths;
}

const FIXED_LIT = buildHuffman(fixedLiteralLengths());
const FIXED_DIST = buildHuffman(new Array<number>(32).fill(5));

class Inflater {
  private input: Uint8Array;
  private inputPos = 0;
  private bitBuf = 0;
  private bitCount = 0;
  private output: number[] = [];

  constructor(input: Uint8Array) {
    this.input = input;
  }

  run(): Uint8Array {
    let last = false;
    while (!last) {
      last = this.bits(1) === 1;
      const type = this.bits(2);
      if (type === 0) this.storedBlock();
      else if (type === 1) this.codes(FIXED_LIT, FIXED_DIST);
      else if (type === 2) {
        const tables = this.dynamic();
        this.codes(tables.lit, tables.dist);
      } else {
        throw new FetchError(400, "Corrupt deflate data");
      }
    }
    return Uint8Array.from(this.output);
  }

  private bits(need: number): number {
    let value = this.bitBuf;
    while (this.bitCount < need) {
      value |= (this.input[this.inputPos++] ?? 0) << this.bitCount;
      this.bitCount += 8;
    }
    this.bitBuf = value >>> need;
    this.bitCount -= need;
    return value & ((1 << need) - 1);
  }

  private decode(h: Huffman): number {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len <= MAXBITS; len++) {
      code |= this.bits(1);
      const count = h.count[len]!;
      if (code - first < count) return h.symbol[index + (code - first)]!;
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return -1;
  }

  private storedBlock(): void {
    this.bitBuf = 0;
    this.bitCount = 0;
    const length = this.read16();
    const nlength = this.read16();
    if ((length ^ 0xffff) !== nlength) throw new FetchError(400, "Corrupt deflate stored block");
    for (let i = 0; i < length; i++) this.output.push(this.input[this.inputPos++] ?? 0);
  }

  private read16(): number {
    return (this.input[this.inputPos++] ?? 0) | ((this.input[this.inputPos++] ?? 0) << 8);
  }

  private codes(lit: Huffman, dist: Huffman): void {
    let sym = this.decode(lit);
    while (sym !== 256) {
      if (this.output.length > MAX_CRX_BYTES) throw new FetchError(400, "Output too large");
      if (sym < 0) throw new FetchError(400, "Corrupt deflate data");
      if (sym < 256) {
        this.output.push(sym);
      } else {
        const li = sym - 257;
        const length = LENGTH_BASE[li]! + this.bits(LENGTH_EXTRA[li]!);
        const dsym = this.decode(dist);
        if (dsym < 0) throw new FetchError(400, "Corrupt deflate data");
        const distance = DIST_BASE[dsym]! + this.bits(DIST_EXTRA[dsym]!);
        const start = this.output.length - distance;
        if (start < 0) throw new FetchError(400, "Corrupt deflate data");
        for (let i = 0; i < length; i++) this.output.push(this.output[start + i]!);
      }
      sym = this.decode(lit);
    }
  }

  private dynamic(): { lit: Huffman; dist: Huffman } {
    const hlit = this.bits(5) + 257;
    const hdist = this.bits(5) + 1;
    const hclen = this.bits(4) + 4;
    const clLengths = new Array<number>(19).fill(0);
    for (let i = 0; i < hclen; i++) clLengths[CODE_LENGTH_ORDER[i]!] = this.bits(3);
    const clTree = buildHuffman(clLengths);
    const lengths = new Array<number>(hlit + hdist).fill(0);
    let i = 0;
    while (i < hlit + hdist) {
      const sym = this.decode(clTree);
      if (sym < 0) throw new FetchError(400, "Corrupt deflate data");
      if (sym < 16) {
        lengths[i++] = sym;
      } else if (sym === 16) {
        const rep = 3 + this.bits(2);
        const prev = lengths[i - 1] ?? 0;
        for (let j = 0; j < rep; j++) lengths[i++] = prev;
      } else if (sym === 17) {
        i += 3 + this.bits(3);
      } else {
        i += 11 + this.bits(7);
      }
    }
    if (i > hlit + hdist) throw new FetchError(400, "Corrupt deflate data");
    return { lit: buildHuffman(lengths.slice(0, hlit)), dist: buildHuffman(lengths.slice(hlit)) };
  }
}

function inflateRaw(data: Uint8Array): Uint8Array {
  return new Inflater(data).run();
}

export function parseManifestJson(data: Uint8Array): Record<string, unknown> {
  try {
    return JSON.parse(stripComments(stripBom(decodeUtf8(data)))) as Record<string, unknown>;
  } catch {
    throw new FetchError(400, "Invalid manifest.json");
  }
}

function parseMessages(data: Uint8Array | null): Record<string, { message: string }> | null {
  if (data === null) return null;
  try {
    return JSON.parse(stripComments(stripBom(decodeUtf8(data)))) as Record<string, { message: string }>;
  } catch {
    throw new FetchError(400, "Invalid messages.json");
  }
}

function stripMarkers(value: string): string {
  const match = /^__MSG_(.+?)__$/.exec(value);
  return match ? match[1]! : value;
}

export function parseCrx(bytes: Uint8Array, id: string): Manifest {
  const zip = bytes.subarray(crxZipOffset(bytes));
  const manifestRaw = readZipEntry(zip, "manifest.json");
  if (!manifestRaw) throw new FetchError(400, "manifest.json not found");
  const manifestJson = parseManifestJson(manifestRaw);
  let messages: Record<string, { message: string }> | null = null;
  const locale = typeof manifestJson.default_locale === "string" ? manifestJson.default_locale : null;
  if (locale) {
    const raw = readZipEntry(zip, `_locales/${locale}/messages.json`) ?? readZipEntry(zip, "_locales/en/messages.json");
    messages = parseMessages(raw);
  }
  return buildManifest(manifestJson, id, messages);
}

function crxZipOffset(bytes: Uint8Array): number {
  if (bytes.length < 12 || decodeUtf8(bytes.subarray(0, 4)) !== "Cr24") {
    throw new FetchError(400, "Not a CRX file");
  }
  const version = u32le(bytes, 4);
  if (version === 3) return 12 + u32le(bytes, 8);
  if (version === 2) {
    if (bytes.length < 16) throw new FetchError(400, "Not a CRX file");
    return 16 + u32le(bytes, 8) + u32le(bytes, 12);
  }
  throw new FetchError(400, `Unsupported CRX version ${version}`);
}

function findEocd(zip: Uint8Array): number {
  const min = Math.max(0, zip.length - 22 - 65535);
  for (let i = zip.length - 22; i >= min; i--) {
    if (u32le(zip, i) === 0x06054b50) return i;
  }
  return -1;
}

function readZipEntry(zip: Uint8Array, name: string): Uint8Array | null {
  const eocd = findEocd(zip);
  if (eocd < 0) throw new FetchError(400, "Invalid ZIP");
  const count = u16le(zip, eocd + 10);
  let off = u32le(zip, eocd + 16);
  for (let i = 0; i < count; i++) {
    if (u32le(zip, off) !== 0x02014b50) throw new FetchError(400, "Invalid ZIP central directory");
    const method = u16le(zip, off + 10);
    const compSize = u32le(zip, off + 20);
    const nameLen = u16le(zip, off + 28);
    const extraLen = u16le(zip, off + 30);
    const commentLen = u16le(zip, off + 32);
    const localOffset = u32le(zip, off + 42);
    const entryName = decodeUtf8(zip.subarray(off + 46, off + 46 + nameLen));
    if (entryName === name) {
      const data = readLocalData(zip, localOffset, compSize);
      if (method === 0) return data;
      if (method === 8) return inflateRaw(data);
      throw new FetchError(400, "Unsupported compression method");
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

function readLocalData(zip: Uint8Array, localOffset: number, compSize: number): Uint8Array {
  if (u32le(zip, localOffset) !== 0x04034b50) throw new FetchError(400, "Invalid ZIP local header");
  const nameLen = u16le(zip, localOffset + 26);
  const extraLen = u16le(zip, localOffset + 28);
  const start = localOffset + 30 + nameLen + extraLen;
  return zip.subarray(start, start + compSize);
}

const TAIL_BYTES = 256 * 1024;

type Ranged = (start: number, end: number) => Promise<Uint8Array>;

/** Central directory entries: name -> local header offset (relative to the ZIP start). */
function centralEntries(zip: Uint8Array): Map<string, { local: number; size: number }> {
  const out = new Map<string, { local: number; size: number }>();
  const eocd = findEocd(zip);
  if (eocd < 0) throw new FetchError(400, "Invalid ZIP");
  let off = u32le(zip, eocd + 16);
  for (let i = 0, n = u16le(zip, eocd + 10); i < n; i++) {
    if (u32le(zip, off) !== 0x02014b50) throw new FetchError(400, "Invalid ZIP central directory");
    const nameLen = u16le(zip, off + 28);
    out.set(decodeUtf8(zip.subarray(off + 46, off + 46 + nameLen)), { local: u32le(zip, off + 42), size: u32le(zip, off + 20) });
    off += 46 + nameLen + u16le(zip, off + 30) + u16le(zip, off + 32);
  }
  return out;
}

/**
 * Large packages (password managers are 25 MB and more) are read with HTTP range requests into a sparse buffer:
 * the head, the ZIP directory at the end, then only manifest.json and the locale files. The existing parser then
 * runs unchanged on the sparse buffer, because it only touches those regions.
 */
async function sparseManifest(total: number, head: Uint8Array, get: Ranged, id: string): Promise<Manifest> {
  const buf = new Uint8Array(total);
  buf.set(head, 0);
  const tailStart = Math.max(head.length, total - TAIL_BYTES);
  buf.set(await get(tailStart, total - 1), tailStart);
  const zipStart = crxZipOffset(buf);
  const zip = buf.subarray(zipStart);
  const eocd = findEocd(zip);
  if (eocd < 0) throw new FetchError(400, "Invalid ZIP");
  const cdStart = zipStart + u32le(zip, eocd + 16);
  if (cdStart < tailStart) buf.set(await get(cdStart, tailStart - 1), cdStart);
  const entries = centralEntries(zip);
  const fill = async (name: string) => {
    const e = entries.get(name);
    if (!e) return;
    const from = zipStart + e.local;
    buf.set(await get(from, Math.min(total - 1, from + 30 + 1024 + e.size)), from);
  };
  await fill("manifest.json");
  const raw = readZipEntry(zip, "manifest.json");
  // Same parser as parseCrx (comments and BOM stripped), so both paths agree on the locale.
  const dl = raw ? parseManifestJson(raw).default_locale : null;
  const locale = typeof dl === "string" ? dl : null;
  if (locale) await Promise.all([fill(`_locales/${locale}/messages.json`), fill("_locales/en/messages.json")]);
  return parseCrx(buf, id);
}

class StreamBuffer {
  private store = new Uint8Array(64 * 1024);
  size = 0;

  append(chunk: Uint8Array): void {
    const need = this.size + chunk.length;
    if (need > this.store.length) {
      let cap = this.store.length * 2;
      while (cap < need) cap *= 2;
      const next = new Uint8Array(cap);
      next.set(this.store.subarray(0, this.size));
      this.store = next;
    }
    this.store.set(chunk, this.size);
    this.size = need;
  }

  data(): Uint8Array {
    return this.store;
  }

  slice(): Uint8Array {
    return this.store.subarray(0, this.size);
  }
}

type Wanted = "manifest" | "locale" | "en" | null;

interface LocalEntry { name: string; method: number; dataStart: number; dataEnd: number; }

async function ensure(buf: StreamBuffer, reader: ReadableStreamDefaultReader<Uint8Array>, need: number): Promise<boolean> {
  while (buf.size < need && buf.size < STREAM_LIMIT) {
    const { value, done } = await reader.read();
    if (done) return false;
    buf.append(value);
  }
  return buf.size >= need;
}

async function readLocalEntry(buf: StreamBuffer, reader: ReadableStreamDefaultReader<Uint8Array>, pos: number): Promise<LocalEntry | "end" | "datadesc"> {
  if (!(await ensure(buf, reader, pos + 30))) return "end";
  if (u32le(buf.data(), pos) !== 0x04034b50) return "end";
  const flags = u16le(buf.data(), pos + 6);
  const method = u16le(buf.data(), pos + 8);
  const compSize = u32le(buf.data(), pos + 18);
  const uncompSize = u32le(buf.data(), pos + 22);
  const nameLen = u16le(buf.data(), pos + 26);
  const extraLen = u16le(buf.data(), pos + 28);
  if ((flags & 0x0008) !== 0 && compSize === 0 && uncompSize === 0) return "datadesc";
  if (!(await ensure(buf, reader, pos + 30 + nameLen))) return "end";
  const name = decodeUtf8(buf.data().subarray(pos + 30, pos + 30 + nameLen));
  const dataStart = pos + 30 + nameLen + extraLen;
  return { name, method, dataStart, dataEnd: dataStart + compSize };
}

async function entryData(buf: StreamBuffer, reader: ReadableStreamDefaultReader<Uint8Array>, entry: LocalEntry): Promise<Uint8Array> {
  if (!(await ensure(buf, reader, entry.dataEnd))) throw new FetchError(400, "Truncated ZIP entry");
  return inflateEntry(buf.data().subarray(entry.dataStart, entry.dataEnd), entry.method);
}

async function readWhole(reader: ReadableStreamDefaultReader<Uint8Array>, buf: StreamBuffer, id: string): Promise<Manifest> {
  let chunk = await reader.read();
  while (!chunk.done) {
    buf.append(chunk.value);
    if (buf.size > MAX_CRX_BYTES) throw new FetchError(413, "Extension package exceeds 60 MB");
    chunk = await reader.read();
  }
  return parseCrx(buf.slice(), id);
}

function inflateEntry(data: Uint8Array, method: number): Uint8Array {
  if (method === 0) return data;
  if (method === 8) return inflateRaw(data);
  throw new FetchError(400, "Unsupported compression method");
}

function wanted(name: string, locale: string | null): Wanted {
  if (name === "manifest.json") return "manifest";
  if (locale === null) return null;
  if (name === `_locales/${locale}/messages.json`) return "locale";
  if (locale !== "en" && name === "_locales/en/messages.json") return "en";
  return null;
}

async function streamManifest(response: Response, id: string): Promise<Manifest> {
  if (!response.body) throw new FetchError(404, "Not on the Chrome Web Store");
  const reader = response.body.getReader();
  const buf = new StreamBuffer();
  await ensure(buf, reader, 16);
  if (buf.size === 0) throw new FetchError(404, "Not on the Chrome Web Store");
  const zipStart = crxZipOffset(buf.slice());
  let manifestJson: Record<string, unknown> | null = null;
  let locale: string | null = null;
  let messages: Uint8Array | null = null;
  let enMessages: Uint8Array | null = null;
  let pos = zipStart;
  while (manifestJson === null || (locale !== null && messages === null)) {
    const entry = await readLocalEntry(buf, reader, pos);
    if (entry === "end") break;
    if (entry === "datadesc") return readWhole(reader, buf, id);
    pos = entry.dataEnd;
    const kind = wanted(entry.name, locale);
    if (kind === "manifest") {
      manifestJson = parseManifestJson(await entryData(buf, reader, entry));
      const dl = manifestJson.default_locale;
      locale = typeof dl === "string" && dl !== "" ? dl : null;
    } else if (kind === "locale") {
      messages = await entryData(buf, reader, entry);
    } else if (kind === "en") {
      enMessages = await entryData(buf, reader, entry);
    }
  }
  await reader.cancel();
  if (manifestJson === null) throw new FetchError(400, "manifest.json not found");
  const manifest = buildManifest(manifestJson, id, parseMessages(messages ?? enMessages ?? null));
  if (messages === null && enMessages === null) {
    manifest.name = stripMarkers(manifest.name);
    manifest.description = stripMarkers(manifest.description);
  }
  return manifest;
}

export async function fetchManifest(id: string, fetchFn?: typeof fetch): Promise<Manifest> {
  const normalized = normalizeId(id);
  if (!normalized) throw new FetchError(400, "Invalid extension id");
  const impl = fetchFn ?? globalThis.fetch;
  const url = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=141.0.0.0&acceptformat=crx2,crx3&x=id%3D${normalized}%26uc`;
  const signal = AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS);
  const first = await impl(url, { redirect: "follow", signal, headers: { range: "bytes=0-65535" } });
  if (first.status === 204) throw new FetchError(404, "Not on the Chrome Web Store");
  if (!first.ok) throw new FetchError(first.status, `Download failed: HTTP ${first.status}`);
  if (first.status === 206) {
    const head = new Uint8Array(await first.arrayBuffer());
    if (head.byteLength === 0) throw new FetchError(404, "Not on the Chrome Web Store");
    const total = Number(/\/(\d+)$/.exec(first.headers.get("content-range") ?? "")?.[1] ?? "0");
    if (!total || total <= head.byteLength) return parseCrx(head, normalized);
    if (total > 200 * 1024 * 1024) throw new FetchError(413, "Extension package exceeds 200 MB");
    const finalUrl = first.url || url;
    const get: Ranged = async (start, end) => {
      const r = await impl(finalUrl, { redirect: "follow", signal, headers: { range: `bytes=${start}-${end}` } });
      if (r.status !== 206) throw new FetchError(502, "The Chrome Web Store did not return the requested part");
      return new Uint8Array(await r.arrayBuffer());
    };
    return sparseManifest(total, head, get, normalized);
  }
  return streamManifest(first, normalized);
}

function buildManifest(raw: Record<string, unknown>, id: string, messages: Record<string, { message: string }> | null): Manifest {
  const lookup = messages ? messageLookup(messages) : null;
  const permissions = asStringArray(raw.permissions);
  const optional = asStringArray(raw.optional_permissions);
  const apiPerms: string[] = [];
  const hostFromPerms: string[] = [];
  for (const p of permissions) (isHostPattern(p) ? hostFromPerms : apiPerms).push(p);
  const optApi: string[] = [];
  const optHost: string[] = [];
  for (const p of optional) (isHostPattern(p) ? optHost : optApi).push(p);
  // Optional hosts are not granted at install; keep them apart so they do not inflate the access score.
  const hostPermissions = dedupe([...asStringArray(raw.host_permissions), ...hostFromPerms]);
  const csp = extractCsp(raw.content_security_policy);
  return {
    id,
    name: msg(raw.name, lookup),
    version: typeof raw.version === "string" ? raw.version : "",
    manifestVersion: typeof raw.manifest_version === "number" ? raw.manifest_version : 0,
    permissions: dedupe(apiPerms),
    optionalPermissions: dedupe([...optApi, ...asStringArray(raw.optional_host_permissions), ...optHost]),
    hostPermissions,
    contentScriptMatches: collectMatches(raw.content_scripts),
    externallyConnectable: collectExternallyConnectable(raw.externally_connectable),
    hasBackground: hasBackground(raw.background),
    csp,
    updateUrl: typeof raw.update_url === "string" ? raw.update_url : null,
    description: msg(raw.description, lookup),
  };
}

function messageLookup(messages: Record<string, { message: string }>): Map<string, string> {
  const map = new Map<string, string>();
  for (const [key, value] of Object.entries(messages)) {
    if (value && typeof value.message === "string") map.set(key.toLowerCase(), value.message);
  }
  return map;
}

function msg(value: unknown, lookup: Map<string, string> | null): string {
  if (typeof value !== "string") return "";
  const match = /^__MSG_(.+?)__$/.exec(value);
  if (!match || !lookup) return value;
  return lookup.get(match[1]!.toLowerCase()) ?? value;
}

function isHostPattern(value: string): boolean {
  return value === "<all_urls>" || value.includes("://");
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

function collectMatches(scripts: unknown): string[] {
  if (!Array.isArray(scripts)) return [];
  const matches: string[] = [];
  for (const entry of scripts) {
    if (entry && typeof entry === "object" && Array.isArray((entry as Record<string, unknown>).matches)) {
      for (const m of (entry as Record<string, unknown>).matches as unknown[]) {
        if (typeof m === "string") matches.push(m);
      }
    }
  }
  return dedupe(matches);
}

function collectExternallyConnectable(value: unknown): string[] {
  if (value && typeof value === "object" && Array.isArray((value as Record<string, unknown>).matches)) {
    const list = ((value as Record<string, unknown>).matches as unknown[]).filter((m): m is string => typeof m === "string");
    return dedupe(list);
  }
  return [];
}

function extractCsp(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (typeof obj.extension_pages === "string") return obj.extension_pages;
    if (typeof obj.sandbox === "string") return obj.sandbox;
  }
  return null;
}

function hasBackground(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const bg = value as Record<string, unknown>;
  return typeof bg.service_worker === "string" || Array.isArray(bg.scripts) || typeof bg.page === "string";
}

function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function stripComments(json: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < json.length) {
    const c = json[i]!;
    if (inString) {
      out += c;
      if (c === "\\") {
        out += json[i + 1] ?? "";
        i += 2;
        continue;
      }
      if (c === '"') inString = false;
      i++;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && json[i + 1] === "/") {
      i += 2;
      while (i < json.length && json[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && json[i + 1] === "*") {
      i += 2;
      while (i < json.length - 1 && !(json[i] === "*" && json[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}
