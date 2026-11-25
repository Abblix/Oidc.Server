// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Abblix.Oidc;

/// <summary>
/// The PKCE code challenge (RFC 7636): what a client sends with its authorization request and an authorization
/// server recomputes from the verifier presented at the token endpoint.
/// </summary>
public static class CodeChallenge
{
    /// <summary>
    /// Calculates the code challenge from a code verifier and a method (RFC 7636 section 4.2).
    /// PKCE involves transforming the code verifier into a code challenge, which the authorization server verifies when
    /// exchanging the authorization code for a token. This method ensures that the correct transformation is applied.
    /// It supports both 'plain' and 'S256' methods, with 'S256' being the recommended approach for stronger security.
    /// </summary>
    /// <param name="method">The PKCE challenge method, either 'plain', 'S256' or 'S512'.</param>
    /// <param name="codeVerifier">The code verifier submitted by the client during the token request.</param>
    /// <returns>The transformed code challenge based on the specified method.</returns>
    public static string Calculate(string method, string codeVerifier) => method switch
    {
        // Encodes the code verifier using SHA256 and URL-safe base64 encoding for 'S256' method.
        CodeChallengeMethods.S256 => Base64Url.EncodeToString(
            SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Encodes the code verifier using SHA512 and URL-safe base64 encoding for 'S512' method.
        CodeChallengeMethods.S512 => Base64Url.EncodeToString(
            SHA512.HashData(Encoding.ASCII.GetBytes(codeVerifier))),

        // Returns the code verifier as-is for the 'plain' method.
        CodeChallengeMethods.Plain => codeVerifier,

        // Throws an exception if an unsupported method is encountered.
        _ => throw new ArgumentOutOfRangeException(nameof(method), $"Unknown code challenge method: {method}"),
    };

    /// <summary>
    /// Whether <paramref name="value"/> has the syntax both a code verifier and a code challenge share: OAuth 2.1
    /// (draft-ietf-oauth-v2-1-17) section 4.1.1 and RFC 7636 sections 4.1 and 4.2, "code-verifier = 43*128unreserved"
    /// and "code-challenge = 43*128unreserved", where "unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"".
    /// </summary>
    /// <param name="value">A code verifier or a code challenge as sent.</param>
    public static bool IsWellFormed(string value)
        => value.Length is >= MinLength and <= MaxLength && !value.AsSpan().ContainsAnyExcept(Unreserved);

    private const int MinLength = 43;
    private const int MaxLength = 128;

    private static readonly SearchValues<char> Unreserved =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
}
