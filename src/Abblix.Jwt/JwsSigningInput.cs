// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Abblix.Jwt;

/// <summary>
/// What a JWS signature is checked over and the signature itself, read from the compact serialization (RFC 7515
/// section 7.1).
/// </summary>
internal static class JwsSigningInput
{
    /// <summary>
    /// The signing input, BASE64URL(header) + '.' + BASE64URL(payload), and the decoded signature; false when the
    /// signature is not valid base64url, which makes the token malformed.
    /// </summary>
    public static bool TryRead(
        string[] jwt,
        out byte[] signingInput,
        [NotNullWhen(true)] out byte[]? signature)
    {
        signingInput = Encoding.UTF8.GetBytes($"{jwt[0]}.{jwt[1]}");
        try
        {
            signature = Base64Url.DecodeFromChars(jwt[2]);
            return true;
        }
        catch (FormatException)
        {
            signature = null;
            return false;
        }
    }
}
