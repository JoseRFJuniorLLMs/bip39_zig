const std = @import("std");
const mem = @import("std").mem;
const fs = @import("std").fs;
const crypto = @import("std").crypto;
const hasher = @import("std").crypto.hash.SHA256;
const hmac = @import("std").crypto.hmac;
const rand = @import("std").rand;

const WORDLIST_FILE = "BIP39.js";

fn readWordlist() ![][]const u8 {
    const file = try fs.cwd().openFile(WORDLIST_FILE, .{});
    defer file.close();

    var buffer: [4096]u8 = undefined;
    const bytesRead = try file.readAll(buffer[0..]);
    return std.json.parse([]const u8, []const u8).maybeInferAllocator(buffer[0..bytesRead]);
}

fn generateEntropy(rng: *rand.Rng, len: usize) [16]u8 {
    var entropy: [16]u8 = undefined;
    _ = rng.fill(entropy[0..len]);
    return entropy;
}

fn deriveMnemonic(entropy: []u8) ![]u8 {
    const seedLen = 64;
    const hashLen = 32;

    var mnemonic: [seedLen]u8 = undefined;
    const hash = try hasher.hash(hmac.new(hasher, entropy, "mnemonic".[]));

    for (hash[0] & 0b11111) |i| {
        mnemonic[i] = hash[i];
    }

    return mnemonic[0..seedLen];
}

fn generateMnemonic(rng: *rand.Rng, words: [][]const u8) ![]u8 {
    const entropyLen = 16;
    const checksumLen = 4;
    const totalLen = entropyLen + checksumLen;
    var entropy: [totalLen]u8 = undefined;
    var mnemonic: [24]u8 = undefined;

    // Gera a entropia
    entropy = generateEntropy(rng, entropyLen);
    // Calcula o checksum
    const hash = try hasher.hash(hmac.new(hasher, entropy, "mnemonic".[]));
    const checksum = hash[0] >> 3;

    // Copia a entropia para a frase
    mem.copy(entropy[entropyLen - 1..totalLen], &checksum, checksumLen);
    for (entropy.len - 1) |i| {
        mnemonic[i] = entropy[i];
    }

    // Converte a entropia em palavras
    for (24) |i| {
        const wordIndex = mnemonic[i] % words.len;
        const wordList = words[wordIndex];
        const subIndex = mnemonic[i] % wordList.len;
        mnemonic[i] = wordList[subIndex];
    }

    return mnemonic;
}

fn generateSeed(mnemonic: []u8) ![]u8 {
    return deriveMnemonic(mnemonic);
}

fn generateExtendedKeys(seed: []u8) !void {
    const seedLen = 64;
    const privateKeyLen = 32;
    const publicKeyLen = 33;
    var privateKey: [privateKeyLen]u8 = undefined;
    var publicKey: [publicKeyLen]u8 = undefined;

    const key = try crypto.keyDerive(seed[0..seedLen]);
    privateKey = key[0..privateKeyLen];
    publicKey = key[privateKeyLen..];

    const privateKeyHex = std.fmt.bufToHex(privateKey);
    const publicKeyHex = std.fmt.bufToHex(publicKey);

    std.debug.print("BIP39 Passphrase: {}\n", .{std.io.getStdIn().readAllAlloc(std.heap.page_allocator)});
    std.debug.print("BIP39 Seed: {}\n", .{std.fmt.bufToHex(seed)});
    std.debug.print("BIP32 Root Key: {}\n", .{privateKeyHex});
    std.debug.print("Account Extended Private Key: {}\n", .{privateKeyHex});
    std.debug.print("Account Extended Public Key: {}\n", .{publicKeyHex});
    std.debug.print("BIP32 Derivation Path: m/44'/0'/0'/0\n");
    std.debug.print("BIP32 Extended Private Key: {}\n", .{privateKeyHex});
    std.debug.print("BIP32 Extended Public Key: {}\n", .{publicKeyHex});
    std.debug.print("Address: (Generated from public key)\n");
    std.debug.print("Public Key: {}\n", .{publicKeyHex});
    std.debug.print("Private Key: {}\n", .{privateKeyHex});
}

pub fn main() void {
    const wordlist = try readWordlist();
    var rng = rand.DefaultPrng.init(std.time.milliTimestamp());
    defer rng.deinit();

    const mnemonic = try generateMnemonic(&rng, wordlist);
    const seed = try generateSeed(mnemonic);
    try generateExtendedKeys(seed);
}
