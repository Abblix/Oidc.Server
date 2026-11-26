// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Client assertions shaped only as far as an authenticator reads one before validating it: the algorithm the header
/// names, and whether it is a JWE.
/// </summary>
public static class AssertionHeaders
{
    /// <summary>The form of an assertion a test presents.</summary>
    public const string Unreadable = "unreadable";

    /// <summary>The form of an assertion a test presents: a compact JWE.</summary>
    public const string Encrypted = "encrypted";

    /// <summary>
    /// An assertion whose header names <paramref name="form"/> as its algorithm, or one of the forms above.
    /// </summary>
    public static string Assertion(string form) => form switch
    {
        Unreadable => "not-base64!.payload.signature",
        // A JWE header names how the content key is managed, here as no signature algorithm of either method
        Encrypted => $"{Header(EncryptionAlgorithms.KeyManagement.RsaOaep)}.key.iv.ciphertext.tag",
        _ => $"{Header(form)}.payload.signature",
    };

    private static string Header(string algorithm)
        => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(
            new JsonObject { [JwtClaimTypes.Algorithm] = algorithm }.ToJsonString()));
}
