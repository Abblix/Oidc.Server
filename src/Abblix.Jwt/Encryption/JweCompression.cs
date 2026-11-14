// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The "zip" (compression algorithm) of a received JWE (RFC 7516 section 4.1.3): "This Header Parameter MUST be
/// understood and processed by implementations". The library reads "DEF" (RFC 1951 DEFLATE) and compresses nothing it
/// issues, as RFC 8725 section 3.6 has it: "Compression of data SHOULD NOT be done before encryption".
/// </summary>
internal static class JweCompression
{
    /// <summary>The one "zip" value RFC 7516 section 4.1.3 defines: compression with DEFLATE.</summary>
    public const string Deflate = "DEF";

    /// <summary>
    /// The most octets a compressed plaintext may inflate to. A few hundred octets of DEFLATE can stand for gigabytes,
    /// and the plaintext of a JWE this library reads is a token or a key, which every channel carrying it holds far
    /// below this size; so inflation stops here rather than growing with whatever a sender compressed.
    /// </summary>
    public const int MaxUncompressedSize = 1024 * 1024;

    private const int ChunkSize = 16 * 1024;

    /// <summary>
    /// Whether the protected header names a compression this library can undo: none, or "DEF".
    /// </summary>
    public static bool IsSupported(JsonWebTokenHeader header)
        => !header.Json.TryGetPropertyValue(JwtClaimTypes.CompressionAlgorithm, out var zip)
           || zip is JsonValue value && value.GetValueKind() == JsonValueKind.String &&
           value.GetValue<string>() == Deflate;

    /// <summary>
    /// RFC 7516 section 5.2 step 17: "If a "zip" parameter was included, uncompress the decrypted plaintext using the
    /// specified compression algorithm." Called with a plaintext whose authentication tag has verified, so nothing is
    /// inflated for a token the key did not open.
    /// </summary>
    public static Result<byte[], JwtValidationError> Uncompress(JsonWebTokenHeader header, byte[] plaintext)
    {
        if (!header.Json.ContainsKey(JwtClaimTypes.CompressionAlgorithm))
            return plaintext;

        try
        {
            using var deflate = new DeflateStream(new MemoryStream(plaintext), CompressionMode.Decompress);
            using var inflated = new MemoryStream();
            var chunk = new byte[ChunkSize];
            int read;
            while ((read = deflate.Read(chunk)) > 0)
            {
                if (inflated.Length + read > MaxUncompressedSize)
                {
                    return new JwtValidationError(
                        JwtError.InvalidToken,
                        $"The compressed JWE plaintext inflates past {MaxUncompressedSize} octets");
                }

                inflated.Write(chunk, 0, read);
            }

            return inflated.ToArray();
        }
        catch (InvalidDataException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "The JWE plaintext is not DEFLATE data");
        }
    }
}
