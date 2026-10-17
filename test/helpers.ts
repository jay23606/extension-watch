import { deflateRawSync } from "node:zlib";

/** A minimal valid CRX3 holding one deflated manifest.json, with a central directory. */
export function manifestCrxForTest(manifest: unknown): Uint8Array {
  const name = Buffer.from("manifest.json");
  const raw = Buffer.from(JSON.stringify(manifest));
  const data = deflateRawSync(raw);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8);
  local.writeUInt32LE(data.length, 18); local.writeUInt32LE(raw.length, 22); local.writeUInt16LE(name.length, 26);
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(8, 10);
  cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(raw.length, 24); cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(0, 42);
  const cdOffset = 30 + name.length + data.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + name.length, 12); eocd.writeUInt32LE(cdOffset, 16);
  const header = Buffer.alloc(12);
  header.write("Cr24", 0); header.writeUInt32LE(3, 4); header.writeUInt32LE(0, 8);
  return new Uint8Array(Buffer.concat([header, local, name, data, cd, name, eocd]));
}
