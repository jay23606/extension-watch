import { FetchError, type Manifest } from "./types";

const DOWNLOAD_TIMEOUT_MS = 8000;
const MAX_CRX_BYTES = 20 * 1024 * 1024;
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

export function parseCrx(bytes: Uint8Array, id: string): Manifest {
  const zip = bytes.subarray(crxZipOffset(bytes));
  const manifestRaw = readZipEntry(zip, "manifest.json");
  if (!manifestRaw) throw new FetchError(400, "manifest.json not found");
  let manifestJson: Record<string, unknown>;
  try {
    manifestJson = JSON.parse(stripComments(stripBom(decodeUtf8(manifestRaw)))) as Record<string, unknown>;
  } catch {
    throw new FetchError(400, "Invalid manifest.json");
  }
  let messages: Record<string, { message: string }> | null = null;
  const locale = typeof manifestJson.default_locale === "string" ? manifestJson.default_locale : null;
  if (locale) {
    const raw = readZipEntry(zip, `_locales/${locale}/messages.json`) ?? readZipEntry(zip, "_locales/en/messages.json");
    if (raw) {
      try {
        messages = JSON.parse(stripComments(stripBom(decodeUtf8(raw)))) as Record<string, { message: string }>;
      } catch {
        throw new FetchError(400, "Invalid messages.json");
      }
    }
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

export async function fetchManifest(id: string, fetchFn?: typeof fetch): Promise<Manifest> {
  const normalized = normalizeId(id);
  if (!normalized) throw new FetchError(400, "Invalid extension id");
  const impl = fetchFn ?? globalThis.fetch;
  const url = `https://clients2.google.com/service/update2/crx?response=redirect&prodversion=141.0.0.0&acceptformat=crx2,crx3&x=id%3D${normalized}%26uc`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT_MS);
  try {
    const response = await impl(url, { redirect: "follow", signal: controller.signal });
    if (response.status === 204) throw new FetchError(404, "Not on the Chrome Web Store");
    if (!response.ok) throw new FetchError(response.status, `Download failed: HTTP ${response.status}`);
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength === 0) throw new FetchError(404, "Not on the Chrome Web Store");
    if (buffer.byteLength > MAX_CRX_BYTES) throw new FetchError(413, "Extension package exceeds 20 MB");
    return parseCrx(new Uint8Array(buffer), normalized);
  } finally {
    clearTimeout(timer);
  }
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
  const hostPermissions = dedupe([...asStringArray(raw.host_permissions), ...hostFromPerms, ...optHost]);
  const csp = extractCsp(raw.content_security_policy);
  return {
    id,
    name: msg(raw.name, lookup),
    version: typeof raw.version === "string" ? raw.version : "",
    manifestVersion: typeof raw.manifest_version === "number" ? raw.manifest_version : 0,
    permissions: dedupe(apiPerms),
    optionalPermissions: dedupe(optApi),
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
