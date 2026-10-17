import { FetchError, type Manifest } from "./types";

const DOWNLOAD_TIMEOUT_MS = 25000;
const MAX_CRX_BYTES = 60 * 1024 * 1024;
const MAX_CHUNKS = 1_000_000;
const MAX_BLOCKS = 1_000_000;
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
    // Each block emits at least one byte or reads at least 3 bits; MAX_BLOCKS bounds a corrupt stream.
    for (let block = 0; !last; block++) {
      if (block >= MAX_BLOCKS) throw new FetchError(400, "Corrupt deflate data");
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
    for (let k = 0; k < 4 && this.bitCount < need; k++) {
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
    // Every symbol adds at least one output byte, and output is capped, so MAX_CRX_BYTES + 1 iterations bound the loop.
    for (let n = 0; sym !== 256; n++) {
      if (n > MAX_CRX_BYTES || this.output.length > MAX_CRX_BYTES) throw new FetchError(400, "Output too large");
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
    // Each code length symbol advances i by at least 1; at most hlit + hdist (<= 320) steps.
    for (let step = 0; i < hlit + hdist && step < 320; step++) {
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
/** Bytes from `from`, up to `len` long (may be shorter at the end of what is available). */
type Reader = (from: number, len: number) => Promise<Uint8Array>;
interface DirEntry { local: number; size: number; method: number }

const INDEX_TAIL_BYTES = 2 * 1024 * 1024;
const CAPTURE_MANIFEST = 512 * 1024;
const CAPTURE_LOCALE = 256 * 1024;
const CAPTURE_BUDGET = 24 * 1024 * 1024;
const MAX_CAPTURES = 400;
const MAX_STREAM_BYTES = 250 * 1024 * 1024;
const HEAD_BYTES = 64 * 1024;
const CARRY_BYTES = 128;
const LOCALE_NAME = /^_locales\/[A-Za-z_-]{2,12}\/messages\.json$/;

/** End of central directory record, searched backwards in the tail (comment up to 64 KB). */
function directoryRef(zipStart: number, tail: Uint8Array): { at: number; size: number; count: number } {
  const min = Math.max(0, tail.length - 22 - 65535);
  for (let i = tail.length - 22; i >= min; i--) {
    if (u32le(tail, i) === 0x06054b50) return { at: zipStart + u32le(tail, i + 16), size: u32le(tail, i + 12), count: u16le(tail, i + 10) };
  }
  throw new FetchError(400, "Invalid ZIP: end of central directory not found");
}

function parseDirectory(cd: Uint8Array, count: number): Map<string, DirEntry> {
  const map = new Map<string, DirEntry>();
  let p = 0;
  for (let n = 0; n < count && p + 46 <= cd.length; n++) {
    if (u32le(cd, p) !== 0x02014b50) throw new FetchError(400, "Invalid ZIP central directory");
    const nameLen = u16le(cd, p + 28);
    const name = decodeUtf8(cd.subarray(p + 46, p + 46 + nameLen));
    if (!map.has(name)) map.set(name, { local: u32le(cd, p + 42), size: u32le(cd, p + 20), method: u16le(cd, p + 10) });
    p += 46 + nameLen + u16le(cd, p + 30) + u16le(cd, p + 32);
  }
  return map;
}

/** Read one entry at the offset the central directory gives. The local header must carry the same name, as in Chrome. */
async function readIndexed(read: Reader, zipStart: number, name: string, e: DirEntry): Promise<Uint8Array> {
  const from = zipStart + e.local;
  const head = await read(from, 30 + 1024 + e.size);
  if (head.length < 30 || u32le(head, 0) !== 0x04034b50) throw new FetchError(400, "Invalid ZIP local header");
  const nameLen = u16le(head, 26);
  if (decodeUtf8(head.subarray(30, 30 + nameLen)) !== name) throw new FetchError(400, "ZIP local header does not match the central directory");
  const start = 30 + nameLen + u16le(head, 28);
  let data = head.subarray(start, start + e.size);
  if (data.length < e.size) data = await read(from + start, e.size);
  if (data.length < e.size) throw new FetchError(422, "Could not read the whole manifest entry");
  return inflateEntry(data, e.method);
}

async function manifestFromIndex(zipStart: number, tail: Uint8Array, tailStart: number, read: Reader, id: string, fetchFn?: typeof fetch): Promise<Manifest> {
  const ref = directoryRef(zipStart, tail);
  const cd = ref.at >= tailStart ? tail.subarray(ref.at - tailStart, ref.at - tailStart + ref.size) : await read(ref.at, ref.size);
  if (cd.length < ref.size) throw new FetchError(422, "The ZIP index of this package is too large to read");
  const entries = parseDirectory(cd, ref.count);
  const me = entries.get("manifest.json");
  if (!me) throw new FetchError(400, "manifest.json not found");
  const json = parseManifestJson(await readIndexed(read, zipStart, "manifest.json", me));
  const dl = json.default_locale;
  let messages: Record<string, { message: string }> | null = null;
  if (typeof dl === "string" && dl !== "") {
    const name = entries.has(`_locales/${dl}/messages.json`) ? `_locales/${dl}/messages.json` : "_locales/en/messages.json";
    const le = entries.get(name);
    try {
      if (le) messages = parseMessages(await readIndexed(read, zipStart, name, le));
    } catch (err) {
      console.log("locale read failed", err instanceof Error ? err.message : "error");
    }
  }
  const manifest = buildManifest(json, id, messages);
  if (manifest.name.includes("__MSG_")) manifest.name = (await storeTitle(id, fetchFn)) ?? stripMarkers(manifest.name);
  if (manifest.description.includes("__MSG_")) manifest.description = "";
  return manifest;
}

function inflateEntry(data: Uint8Array, method: number): Uint8Array {
  if (method === 0) return data;
  if (method === 8) return inflateRaw(data);
  throw new FetchError(400, "Unsupported compression method");
}

interface Segment { start: number; bytes: Uint8Array; len: number }

function segmentReader(segments: Segment[]): Reader {
  // Captures can overlap (a long capture runs into the next entry), so take the segment that holds the most bytes from `from`.
  return async (from, len) => {
    let best: Segment | null = null;
    for (const seg of segments) {
      if (from >= seg.start && from < seg.start + seg.len && (!best || seg.start + seg.len > best.start + best.len)) best = seg;
    }
    if (!best) throw new FetchError(422, "A needed part of this package was not kept while streaming");
    return best.bytes.subarray(from - best.start, Math.min(best.len, from - best.start + len));
  };
}

interface Capture extends Segment { cap: number }

/** Collects the bytes after every local header named manifest.json or _locales/<x>/messages.json while the package streams past.
 * Buffers grow on demand, and a capture ends where the next local header starts (ZIP entries are contiguous), so memory follows
 * the size of the wanted entries, not the package. A spoofed header can only cut a capture short, which fails the read (closed). */
class Capturer {
  readonly captures: Capture[] = [];
  private readonly seen = new Set<number>();
  private budget = CAPTURE_BUDGET;
  private carry = new Uint8Array(0);

  feed(chunk: Uint8Array, chunkStart: number): void {
    for (const c of this.captures) if (c.len < c.cap) this.append(c, chunk.subarray(0, Math.min(c.cap - c.len, chunk.length)));
    // Headers that start in the last bytes of the previous chunk: scan a small strip, not a copy of the whole chunk.
    const carry = this.carry;
    if (carry.length > 0) {
      const strip = new Uint8Array(carry.length + Math.min(chunk.length, CARRY_BYTES));
      strip.set(carry, 0);
      strip.set(chunk.subarray(0, strip.length - carry.length), carry.length);
      for (let i = strip.indexOf(0x50); i >= 0 && i < carry.length; i = strip.indexOf(0x50, i + 1)) {
        if (isLocalHeader(strip, i)) this.header(strip, i, chunkStart - carry.length, (c) => this.append(c, chunk));
      }
    }
    for (let i = chunk.indexOf(0x50); i >= 0; i = chunk.indexOf(0x50, i + 1)) {
      if (isLocalHeader(chunk, i)) this.header(chunk, i, chunkStart, null);
    }
    // Keep the last CARRY_BYTES of the stream, even when chunks are smaller than that.
    if (chunk.length >= CARRY_BYTES) {
      this.carry = chunk.slice(chunk.length - CARRY_BYTES);
    } else {
      const joined = new Uint8Array(carry.length + chunk.length);
      joined.set(carry, 0);
      joined.set(chunk, carry.length);
      this.carry = joined.slice(Math.max(0, joined.length - CARRY_BYTES));
    }
  }

  /** `rest` appends the remainder of the current chunk when the header was found in the boundary strip. */
  private header(buf: Uint8Array, i: number, base: number, rest: ((c: Capture) => void) | null): void {
    this.closeBefore(base + i);
    // In the strip, the bytes before carry.length belong to the previous chunk; `rest` then adds the whole current chunk.
    const c = this.consider(buf, i, base, rest ? this.carry.length : buf.length);
    if (c && rest) rest(c);
  }

  private append(c: Capture, part: Uint8Array): void {
    if (c.len + part.length > c.bytes.length) {
      let size = c.bytes.length * 2;
      for (let k = 0; k < 32 && size < c.len + part.length; k++) size *= 2;
      const next = new Uint8Array(Math.min(c.cap, size));
      next.set(c.bytes.subarray(0, c.len));
      c.bytes = next;
    }
    c.bytes.set(part, c.len);
    c.len += part.length;
  }

  /** A new local header at `abs` ends every capture that started before it. */
  private closeBefore(abs: number): void {
    for (const c of this.captures) {
      if (c.start < abs && c.start + c.cap > abs) {
        c.cap = abs - c.start;
        c.len = Math.min(c.len, c.cap);
      }
    }
  }

  /** Start a capture for a wanted header at buf[i]; it takes buf[i..end). Returns it, or null. */
  private consider(buf: Uint8Array, i: number, base: number, end: number): Capture | null {
    if (i + 30 > buf.length) return null;
    const nameLen = u16le(buf, i + 26);
    if (nameLen > 64 || i + 30 + nameLen > buf.length) return null;
    const name = decodeUtf8(buf.subarray(i + 30, i + 30 + nameLen));
    const cap = name === "manifest.json" ? CAPTURE_MANIFEST : LOCALE_NAME.test(name) ? CAPTURE_LOCALE : 0;
    const abs = base + i;
    if (cap === 0 || this.seen.has(abs) || this.budget < cap || this.captures.length >= MAX_CAPTURES) return null;
    this.seen.add(abs);
    this.budget -= cap;
    const c: Capture = { start: abs, bytes: new Uint8Array(Math.min(cap, 16 * 1024)), len: 0, cap };
    this.captures.push(c);
    this.append(c, buf.subarray(i, Math.min(end, i + cap)));
    return c;
  }
}

function isLocalHeader(b: Uint8Array, i: number): boolean {
  return i + 4 <= b.length && b[i + 1] === 0x4b && b[i + 2] === 3 && b[i + 3] === 4;
}

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

/** Google ignores Range for large packages: stream the whole package once, keeping only the head, a rolling tail and the captured entries. */
async function streamManifest(response: Response, id: string, fetchFn?: typeof fetch): Promise<Manifest> {
  if (!response.body) throw new FetchError(404, "Not on the Chrome Web Store");
  const reader = response.body.getReader();
  const capturer = new Capturer();
  const headChunks: Uint8Array[] = [];
  const tailChunks: Uint8Array[] = [];
  let headLen = 0;
  let tailLen = 0;
  let pos = 0;
  for (let n = 0; n < MAX_CHUNKS; n++) {
    const { value, done } = await reader.read();
    if (done) break;
    capturer.feed(value, pos);
    if (headLen < HEAD_BYTES) { headChunks.push(value); headLen += value.length; }
    tailChunks.push(value);
    tailLen += value.length;
    for (let k = 0; k < MAX_CHUNKS && tailChunks.length > 1 && tailLen - tailChunks[0]!.length >= INDEX_TAIL_BYTES; k++) tailLen -= tailChunks.shift()!.length;
    pos += value.length;
    if (pos > MAX_STREAM_BYTES) { await reader.cancel(); throw new FetchError(413, "Extension package exceeds 250 MB"); }
  }
  if (pos === 0) throw new FetchError(404, "Not on the Chrome Web Store");
  const head = concatChunks(headChunks, headLen);
  const tail = concatChunks(tailChunks, tailLen);
  const zipStart = crxZipOffset(head);
  const read = segmentReader([{ start: 0, bytes: head, len: head.length }, { start: pos - tail.length, bytes: tail, len: tail.length }, ...capturer.captures]);
  return manifestFromIndex(zipStart, tail, pos - tail.length, read, id, fetchFn);
}

/** Display name from the extension's Web Store page title, used when the locale file is too deep in a large package. */
export async function storeTitle(id: string, fetchFn: typeof fetch = globalThis.fetch): Promise<string | null> {
  try {
    const res = await fetchFn(`https://chromewebstore.google.com/detail/${id}`, { redirect: "follow", signal: AbortSignal.timeout(5000), headers: { "accept-language": "en" } });
    if (!res.ok || !res.body) return null;
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let text = "";
    for (let read = 0; read < 1_500_000;) {
      const { value, done } = await reader.read();
      if (done) break;
      read += value.byteLength;
      text = (text + dec.decode(value, { stream: true })).slice(-200_000);
      const m = /<title>([^<]{1,200}?) - Chrome Web Store<\/title>/.exec(text);
      if (m) { await reader.cancel(); return decodeEntities(m[1] ?? "").trim() || null; }
    }
    await reader.cancel();
    return null;
  } catch (err) {
    console.log("store title failed", err instanceof Error ? err.name : "error");
    return null;
  }
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
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
    const total = Number(/\/(\d+)$/.exec(first.headers.get("content-range") ?? "")?.[1] ?? "0") || head.byteLength;
    if (total > MAX_STREAM_BYTES) throw new FetchError(413, "Extension package exceeds 250 MB");
    const finalUrl = first.url || url;
    const get: Ranged = async (start, end) => {
      const r = await impl(finalUrl, { redirect: "follow", signal, headers: { range: `bytes=${start}-${end}` } });
      if (r.status !== 206) throw new FetchError(502, "The Chrome Web Store did not return the requested part");
      return new Uint8Array(await r.arrayBuffer());
    };
    const zipStart = crxZipOffset(head);
    const tailStart = Math.max(0, total - TAIL_BYTES);
    const tail = total <= head.byteLength ? head : await get(tailStart, total - 1);
    const read: Reader = async (from, len) => (from + len <= head.byteLength ? head.subarray(from, from + len) : get(from, Math.min(total, from + len) - 1));
    return manifestFromIndex(zipStart, tail, total <= head.byteLength ? 0 : tailStart, read, normalized, fetchFn);
  }
  return streamManifest(first, normalized, fetchFn);
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
  for (let guard = 0; i < json.length && guard <= json.length; guard++) {
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
      for (; i < json.length && json[i] !== "\n"; i++);
      continue;
    }
    if (c === "/" && json[i + 1] === "*") {
      i += 2;
      for (; i < json.length - 1 && !(json[i] === "*" && json[i + 1] === "/"); i++);
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}
