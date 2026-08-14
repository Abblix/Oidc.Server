// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Utils.Polyfills;

namespace Abblix.Jwt;

/// <summary>
/// Computes the detached-signature hashes an ID Token carries for values delivered beside it:
/// <c>at_hash</c> for an access token and <c>c_hash</c> for an authorization code.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 gives one recipe for all of them, in section 3.2.2.9 for <c>at_hash</c> and
/// section 3.3.2.10 for <c>c_hash</c>: hash the ASCII octets of the value with the algorithm JWA pairs
/// with the <c>alg</c> of the ID Token's own JOSE header, take the left-most half of the digest, and
/// base64url-encode it.
/// The point of the construction is to bind the ID Token to the value: an attacker who swaps the code
/// or the access token for one of their own is caught, because the signed ID Token still carries the
/// hash of the original. Which is why the issuing and the verifying side must compute it identically -
/// they live in different packages, and this is the single place both take it from.
/// </remarks>
public static class HashCalculator
{
    /// <summary>
    /// Returns the base64url-encoded left-most half of <paramref name="value"/>'s digest, or
    /// <see langword="null"/> when <paramref name="signingAlgorithm"/> has no hash paired with it.
    /// </summary>
    /// <param name="signingAlgorithm">The <c>alg</c> from the ID Token's JOSE header.</param>
    /// <param name="value">The access token, authorization code or state to bind.</param>
    /// <remarks>
    /// The pairing is by digest size rather than by signature family, because every JWS algorithm name
    /// ends in the size of the hash it uses: RS256, PS256, ES256 and HS256 all pair with SHA-256, and
    /// so on up. ES512 is the one that looks irregular and is not - it signs with SHA-512, matching its
    /// name rather than its P-521 curve.
    /// A null result is a real answer, not a failure to compute: <c>none</c> has no digest, and neither
    /// does an algorithm this library does not recognise. The two sides then part ways, which is why
    /// the decision is left here to the caller - an issuer omits the claim, while a client MUST refuse
    /// to treat the binding as satisfied, since "no hash was computable" and "the hash matched" would
    /// otherwise look the same to it.
    /// </remarks>
    public static string? Compute(string signingAlgorithm, string value)
    {
        return ComputeDigest(signingAlgorithm, value) switch
        {
            {} digest => Base64Url.EncodeToString(digest.AsSpan(0, digest.Length >> 1)),
            null => null,
        };
    }

    private static byte[]? ComputeDigest(string signingAlgorithm, string value)
    {
        // ASCII, not UTF-8: section 3.2.2.9 says "the ASCII representation" of the value, and every
        // value this binds - an access token, a code, a state - is drawn from an ASCII alphabet.
        var octets = Encoding.ASCII.GetBytes(value);

        return signingAlgorithm switch
        {
            SigningAlgorithms.RS256 or
            SigningAlgorithms.PS256 or
            SigningAlgorithms.ES256 or
            SigningAlgorithms.HS256 => SHA256.HashData(octets),

            SigningAlgorithms.RS384 or
            SigningAlgorithms.PS384 or
            SigningAlgorithms.ES384 or
            SigningAlgorithms.HS384 => SHA384.HashData(octets),

            SigningAlgorithms.RS512 or
            SigningAlgorithms.PS512 or
            SigningAlgorithms.ES512 or
            SigningAlgorithms.HS512 => SHA512.HashData(octets),

            _ => null,
        };
    }
}
