// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The body of a Transit <c>sign/{key}</c> call.
/// </summary>
/// <remarks>
/// A named contract rather than an anonymous shape per algorithm: Transit's field names are snake_case, so an
/// anonymous object carries the wire format in its member names, where nothing checks them and every algorithm
/// branch repeats them. Here the names are stated once, as attributes, and each branch supplies only what differs.
/// </remarks>
internal sealed record SignRequest
{
    /// <summary>The signing input, base64-encoded, which Transit hashes itself.</summary>
    [JsonPropertyName("input")]
    public required string Input { get; init; }

    /// <summary>
    /// Whether the input arrives already hashed. It never does here: the JWS signing input is the raw bytes, and
    /// Transit applies <see cref="HashAlgorithm"/> to them.
    /// </summary>
    [JsonPropertyName("prehashed")]
    public bool Prehashed { get; init; }

    /// <summary>The digest Transit applies, in its own spelling (<c>sha2-256</c> and so on).</summary>
    [JsonPropertyName("hash_algorithm")]
    public required string HashAlgorithm { get; init; }

    /// <summary>
    /// The RSA padding, <c>pkcs1v15</c> or <c>pss</c>. Omitted for an EC key, which has no padding to choose.
    /// </summary>
    [JsonPropertyName("signature_algorithm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SignatureAlgorithm { get; init; }

    /// <summary>
    /// How an EC signature is encoded. <c>jws</c> asks for raw R||S, which is what JWS wants; Transit's default
    /// is ASN.1 DER, which would need converting. Omitted for an RSA key.
    /// </summary>
    [JsonPropertyName("marshaling_algorithm")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MarshalingAlgorithm { get; init; }

    /// <summary>
    /// The exact key version to sign with, pinned rather than left to Transit's latest: the produce role picks a
    /// version by the published <c>kid</c>, and the signature must come from that one.
    /// </summary>
    [JsonPropertyName("key_version")]
    public required int KeyVersion { get; init; }
}
