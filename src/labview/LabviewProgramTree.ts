import { crc32 } from "node:zlib";

import { BinaryReader } from "../domain/binaryContainer.js";
import { scanZipDirectory } from "../domain/desktop/zipDirectory.js";
import { decodeStrictUtf8 } from "../domain/strictUtf8.js";
import { decodeZipCp437 } from "../domain/zip/zipEntryText.js";
import {
  ZIP_EXTRA_FIELD,
  lastZipExtraField,
} from "../domain/zip/zipExtraFields.js";

const UTF8_NAME = 0x08_00;
const ENCRYPTED = 0x00_01;
const ZIP64_SIZE = 0xffff_ffff;
const ZIP64_EXTRA = 0x00_01;
const CENTRAL_FIXED_BYTES = 46;
const ZIP64_FIELD_BYTES = 8;

export interface LabviewProgramTreeMember {
  /** Path exactly as the central directory records it. */
  readonly name: string;
  /** Uncompressed bytes the central directory declares. */
  readonly bytes: number;
  /** Stored bytes the central directory declares. */
  readonly storedBytes: number;
  /** ZIP compression method, preserved as declared. */
  readonly method: number;
  /** Whether the entry declares ZIP encryption. */
  readonly encrypted: boolean;
}

export interface LabviewProgramTree {
  /** File members in the archive; directory entries are omitted. */
  readonly entryCount: number;
  /** Sum of the members' declared uncompressed sizes. */
  readonly totalBytes: number;
  readonly members: readonly LabviewProgramTreeMember[];
}

export type ProgramTreeScan =
  | { readonly ok: true; readonly value: LabviewProgramTree }
  | { readonly ok: false; readonly reason: string };

/** A positional reader over one central-directory record kept by the shared reader. */
const recordReader = (record: Uint8Array): BinaryReader =>
  new BinaryReader(
    Buffer.from(record.buffer, record.byteOffset, record.byteLength),
    true,
    "zip",
  );

/**
 * The recorded name: the UTF-8 flag, then the Info-ZIP Unicode Path extra field
 * (0x7075) when its CRC32 matches, then the legacy CP437 mapping the shared ZIP
 * reader uses. A name that must be UTF-8 but is not is unreadable.
 */
const memberName = (
  reader: BinaryReader,
  name: Uint8Array,
  extraStart: number,
  extraEnd: number,
  flags: number,
): string | undefined => {
  if ((flags & UTF8_NAME) !== 0) {
    try {
      return decodeStrictUtf8(name, "preserve");
    } catch {
      return undefined;
    }
  }
  const selected = lastZipExtraField(
    reader,
    extraStart,
    extraEnd,
    ZIP_EXTRA_FIELD.unicodePath,
  );
  if (selected.ok && selected.value !== undefined) {
    const { start, end } = selected.value;
    // The field is authoritative only when its version and name CRC agree.
    if (
      end - start >= 5 &&
      reader.bytes[start] === 1 &&
      reader.u32(start + 1) === crc32(name)
    ) {
      try {
        return decodeStrictUtf8(
          reader.bytes.subarray(start + 5, end),
          "preserve",
        );
      } catch {
        return undefined;
      }
    }
  }
  return decodeZipCp437(name);
};

/** Read the two sizes, resolving the Zip64 extra field for saturated ones. */
const memberSizes = (
  reader: BinaryReader,
  extraStart: number,
  extraEnd: number,
): { readonly bytes: number; readonly storedBytes: number } | undefined => {
  let bytes = reader.u32(24);
  let storedBytes = reader.u32(20);
  if (bytes !== ZIP64_SIZE && storedBytes !== ZIP64_SIZE)
    return { bytes, storedBytes };
  const selected = lastZipExtraField(reader, extraStart, extraEnd, ZIP64_EXTRA);
  if (!selected.ok || selected.value === undefined) return undefined;
  let at = selected.value.start;
  const field = (): number | undefined => {
    if (at + ZIP64_FIELD_BYTES > selected.value!.end) return undefined;
    const value = Number(reader.word(at, 64));
    at += ZIP64_FIELD_BYTES;
    return Number.isSafeInteger(value) ? value : undefined;
  };
  // The Zip64 field holds only the saturated values, in this order.
  if (bytes === ZIP64_SIZE) {
    const value = field();
    if (value === undefined) return undefined;
    bytes = value;
  }
  if (storedBytes === ZIP64_SIZE) {
    const value = field();
    if (value === undefined) return undefined;
    storedBytes = value;
  }
  return { bytes, storedBytes };
};

/**
 * Read the member inventory of the ZIP archive a LabVIEW embedded program tree
 * (`LVzp`) carries. The shared directory reader owns end-record selection,
 * Zip64 resolution, single-volume checks and full-directory consumption; this
 * module interprets each admitted record's name and sizes only. No member is
 * extracted, inflated, or written.
 */
export const parseProgramTreeZip = (bytes: Uint8Array): ProgramTreeScan => {
  // Keep every file record; the archive is bounded by the decode allowance
  // before it reaches this reader.
  const directory = scanZipDirectory(bytes, Number.MAX_SAFE_INTEGER);
  if (directory === undefined)
    return {
      ok: false,
      reason: "its ZIP central directory is damaged or spans multiple disks",
    };
  const members: LabviewProgramTreeMember[] = [];
  let totalBytes = 0;
  for (const record of directory.records) {
    const reader = recordReader(record);
    const flags = reader.u16(8);
    const method = reader.u16(10);
    const nameBytes = reader.u16(28);
    const extraBytes = reader.u16(30);
    const extraAt = CENTRAL_FIXED_BYTES + nameBytes;
    const extraEnd = extraAt + extraBytes;
    const name = memberName(
      reader,
      reader.bytes.subarray(CENTRAL_FIXED_BYTES, extraAt),
      extraAt,
      extraEnd,
      flags,
    );
    if (name === undefined)
      return { ok: false, reason: "a member name is not valid UTF-8" };
    const sizes = memberSizes(reader, extraAt, extraEnd);
    if (sizes === undefined)
      return { ok: false, reason: "a member size is out of range" };
    members.push({
      name,
      bytes: sizes.bytes,
      storedBytes: sizes.storedBytes,
      method,
      encrypted: (flags & ENCRYPTED) !== 0,
    });
    totalBytes += sizes.bytes;
  }
  return {
    ok: true,
    value: { entryCount: directory.count, totalBytes, members },
  };
};
