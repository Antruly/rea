import { crc32 } from "node:zlib";
import { describe, expect, it } from "vitest";

import { parseProgramTreeZip } from "./LabviewProgramTree.js";
import { labviewZipArchive } from "../../tests/fixtures/labview/rsrc.js";

const names = (scan: ReturnType<typeof parseProgramTreeZip>): string[] =>
  scan.ok ? scan.value.members.map(({ name }) => name) : [];

describe("parseProgramTreeZip", () => {
  it("lists file members and omits directory entries", () => {
    const scan = parseProgramTreeZip(
      labviewZipArchive([
        { name: "a.vi", content: Buffer.from("one") },
        { name: "lib/", content: Buffer.alloc(0) },
        { name: "lib/b.vi", content: Buffer.from("two") },
      ]),
    );
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    expect(scan.value.entryCount).toBe(2);
    expect(scan.value.totalBytes).toBe(6);
    expect(scan.value.members.map(({ name }) => name)).toEqual([
      "a.vi",
      "lib/b.vi",
    ]);
  });

  it("reports the declared sizes and encryption flag", () => {
    const scan = parseProgramTreeZip(
      labviewZipArchive([
        { name: "plain.vi", content: Buffer.from("abc") },
        { name: "locked.vi", content: Buffer.from("abcd"), encrypted: true },
      ]),
    );
    expect(scan.ok).toBe(true);
    if (!scan.ok) return;
    expect(scan.value.members[0]).toMatchObject({
      bytes: 3,
      storedBytes: 3,
      method: 0,
      encrypted: false,
    });
    expect(scan.value.members[1]).toMatchObject({
      bytes: 4,
      encrypted: true,
    });
  });

  it("decodes a UTF-8 name when the entry flag says so", () => {
    const scan = parseProgramTreeZip(
      labviewZipArchive([
        { name: "café.vi", content: Buffer.from("x"), utf8: true },
      ]),
    );
    expect(names(scan)).toEqual(["café.vi"]);
  });

  it("uses the Info-ZIP Unicode Path extra field when its CRC matches", () => {
    const recorded = Buffer.from("legacy.vi", "latin1");
    const unicode = Buffer.from("日本語.vi", "utf8");
    const extra = Buffer.alloc(4 + 5 + unicode.length);
    extra.writeUInt16LE(0x70_75, 0);
    extra.writeUInt16LE(5 + unicode.length, 2);
    extra.writeUInt8(1, 4);
    extra.writeUInt32LE(crc32(recorded) >>> 0, 5);
    unicode.copy(extra, 9);
    const scan = parseProgramTreeZip(
      labviewZipArchive([
        { name: "legacy.vi", content: Buffer.from("x"), extra },
      ]),
    );
    expect(names(scan)).toEqual(["日本語.vi"]);
  });

  it("accepts an empty archive", () => {
    const scan = parseProgramTreeZip(labviewZipArchive([]));
    expect(scan.ok && scan.value.entryCount).toBe(0);
  });

  it("preserves a leading BOM in a UTF-8 name", () => {
    const scan = parseProgramTreeZip(
      labviewZipArchive([
        { name: "\uFEFFdemo.vi", content: Buffer.from("x"), utf8: true },
      ]),
    );
    expect(names(scan)).toEqual(["\uFEFFdemo.vi"]);
  });

  it("rejects conflicting end-record counts", () => {
    const archive = Buffer.from(
      labviewZipArchive([
        { name: "a.vi", content: Buffer.from("1") },
        { name: "b.vi", content: Buffer.from("2") },
      ]),
    );
    // Declare one total entry while the on-disk count still says two.
    archive.writeUInt16LE(1, archive.length - 12);
    const scan = parseProgramTreeZip(archive);
    expect(scan.ok).toBe(false);
    if (!scan.ok) expect(scan.reason).toContain("central directory");
  });

  it("rejects a count that stops before the directory ends", () => {
    const archive = Buffer.from(
      labviewZipArchive([
        { name: "a.vi", content: Buffer.from("1") },
        { name: "b.vi", content: Buffer.from("2") },
      ]),
    );
    // Both counts say one, but the directory still holds two records.
    archive.writeUInt16LE(1, archive.length - 14);
    archive.writeUInt16LE(1, archive.length - 12);
    const scan = parseProgramTreeZip(archive);
    expect(scan.ok).toBe(false);
    if (!scan.ok) expect(scan.reason).toContain("central directory");
  });

  it("rejects a multi-disk archive", () => {
    const archive = Buffer.from(labviewZipArchive([]));
    archive.writeUInt16LE(1, archive.length - 18);
    const scan = parseProgramTreeZip(archive);
    expect(scan.ok).toBe(false);
    if (!scan.ok) expect(scan.reason).toContain("multiple disks");
  });

  it("rejects a declared directory larger than the archive", () => {
    const archive = Buffer.from(labviewZipArchive([]));
    archive.writeUInt32LE(0xff_ff_ff_00, archive.length - 10);
    const scan = parseProgramTreeZip(archive);
    expect(scan.ok).toBe(false);
    if (!scan.ok) expect(scan.reason).toContain("central directory");
  });

  it("rejects bytes with no end record", () => {
    const scan = parseProgramTreeZip(Buffer.from("not a zip at all"));
    expect(scan.ok).toBe(false);
  });

  it("does not mistake a stray signature inside a comment for the end record", () => {
    const archive = Buffer.from(labviewZipArchive([]));
    const comment = Buffer.alloc(30);
    comment.writeUInt32LE(0x06_05_4b_50, 0);
    comment.writeUInt16LE(5, 20);
    archive.writeUInt16LE(comment.length, archive.length - 2);
    const scan = parseProgramTreeZip(Buffer.concat([archive, comment]));
    expect(scan.ok).toBe(true);
    if (scan.ok) expect(scan.value.entryCount).toBe(0);
  });
});
