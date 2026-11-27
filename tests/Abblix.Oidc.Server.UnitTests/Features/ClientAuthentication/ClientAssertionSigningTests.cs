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
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The JOSE header of a client assertion is read without verifying anything: the algorithm it names, null where it
/// names none or does not read, and whether the assertion is a JWE.
/// </summary>
public class ClientAssertionSigningTests
{
    private static readonly string Payload = Encode(new JsonObject());

    [Theory]
    [InlineData(SigningAlgorithms.HS256)]
    [InlineData(SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.None)]
    [InlineData("XS512")]
    public void TheAlgorithmTheHeaderNames_IsRead(string algorithm)
    {
        var jws = $"{Encode(new JsonObject { [JwtClaimTypes.Algorithm] = algorithm })}.{Payload}.";

        Assert.Equal(algorithm, ClientAssertionSigning.AlgorithmOf(jws));
        Assert.False(ClientAssertionSigning.IsEncrypted(jws));
    }

    /// <summary>
    /// A header that is not base64url, or not of a JSON object, or names no algorithm, names none.
    /// </summary>
    [Theory]
    [InlineData("not-base64!.payload.signature")]
    [InlineData("two.parts")]
    [InlineData("")]
    public void AnUnreadableHeader_NamesNoAlgorithm(string assertion)
        => Assert.Null(ClientAssertionSigning.AlgorithmOf(assertion));

    [Fact]
    public void AHeaderWithoutAnAlgorithm_NamesNone()
        => Assert.Null(ClientAssertionSigning.AlgorithmOf($"{Encode(new JsonObject())}.{Payload}."));

    [Fact]
    public void AJwe_IsEncrypted()
        => Assert.True(ClientAssertionSigning.IsEncrypted("header.key.iv.ciphertext.tag"));

    private static string Encode(JsonObject json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json.ToJsonString()));
}
