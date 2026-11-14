// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Frozen;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Builds the Transit sign request for a JWS algorithm, pinned to the key version the <c>kid</c> names: the produce
/// role signs with the active version even when a newer one is already published but still propagating.
/// </summary>
/// <remarks>
/// An algorithm decides two things independently: which digest, and how the signature is formed. RSA picks a
/// padding (<c>signature_algorithm</c>), EC picks an encoding (<c>marshaling_algorithm=jws</c>, so Transit returns
/// the R||S form JWS needs instead of ASN.1 DER), so the request differs by exactly one field between the families.
/// </remarks>
internal static class TransitSignRequests
{
    /// <summary>
    /// The Transit fields each JWS algorithm sets; an algorithm absent here is not signed by Transit.
    /// </summary>
    private static readonly FrozenDictionary<string, SignatureForm> FormsByAlgorithm =
        new Dictionary<string, SignatureForm>
        {
            [SigningAlgorithms.RS256] = SignatureForm.Rsa(HashAlgorithms.Sha2With256, SignatureAlgorithms.Pkcs1V15),
            [SigningAlgorithms.RS384] = SignatureForm.Rsa(HashAlgorithms.Sha2With384, SignatureAlgorithms.Pkcs1V15),
            [SigningAlgorithms.RS512] = SignatureForm.Rsa(HashAlgorithms.Sha2With512, SignatureAlgorithms.Pkcs1V15),

            [SigningAlgorithms.PS256] = SignatureForm.Rsa(HashAlgorithms.Sha2With256, SignatureAlgorithms.Pss),
            [SigningAlgorithms.PS384] = SignatureForm.Rsa(HashAlgorithms.Sha2With384, SignatureAlgorithms.Pss),
            [SigningAlgorithms.PS512] = SignatureForm.Rsa(HashAlgorithms.Sha2With512, SignatureAlgorithms.Pss),

            [SigningAlgorithms.ES256] = SignatureForm.Ec(HashAlgorithms.Sha2With256),
            [SigningAlgorithms.ES384] = SignatureForm.Ec(HashAlgorithms.Sha2With384),
            [SigningAlgorithms.ES512] = SignatureForm.Ec(HashAlgorithms.Sha2With512),
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>
    /// The sign request for <paramref name="algorithm"/> over the base64-encoded <paramref name="input"/>, pinned
    /// to <paramref name="version"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">Transit does not sign <paramref name="algorithm"/>.</exception>
    public static SignRequest For(string algorithm, string input, int version)
    {
        if (!FormsByAlgorithm.TryGetValue(algorithm, out var form))
            throw new NotSupportedException($"The Vault Transit store does not sign '{algorithm}'.");

        return new SignRequest
        {
            Input = input,
            HashAlgorithm = form.HashAlgorithm,
            SignatureAlgorithm = form.SignatureAlgorithm,
            MarshalingAlgorithm = form.MarshalingAlgorithm,
            KeyVersion = version,
        };
    }

    private sealed record SignatureForm(string HashAlgorithm, string? SignatureAlgorithm, string? MarshalingAlgorithm)
    {
        public static SignatureForm Rsa(string hashAlgorithm, string padding) => new(hashAlgorithm, padding, null);

        public static SignatureForm Ec(string hashAlgorithm) => new(hashAlgorithm, null, MarshalingAlgorithms.Jws);
    }

    private static class SignatureAlgorithms
    {
        public const string Pkcs1V15 = "pkcs1v15";
        public const string Pss = "pss";
    }

    private static class HashAlgorithms
    {
        public const string Sha2With256 = "sha2-256";
        public const string Sha2With384 = "sha2-384";
        public const string Sha2With512 = "sha2-512";
    }

    private static class MarshalingAlgorithms
    {
        public const string Jws = "jws";
    }
}
