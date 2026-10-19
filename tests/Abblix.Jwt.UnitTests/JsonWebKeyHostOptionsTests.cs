// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A key is a protocol object other parties read member by member, so the options a host serializes its own
/// payloads with must not reach it: not the host's converters, nor case-insensitive member names.
/// </summary>
public class JsonWebKeyHostOptionsTests
{
    /// <summary>
    /// What ASP.NET Core and System.Net.Http.Json start from: member names matched without regard to case.
    /// </summary>
    private static readonly JsonSerializerOptions WebOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// A host that upper-cases every string it serializes, as a global sanitizing converter might.
    /// </summary>
    private static readonly JsonSerializerOptions UpperCasingOptions = new()
    {
        Converters = { new UpperCasingStringConverter() },
    };

    [Fact]
    public void AHostStringConverter_DoesNotRewriteTheMembersOfAKeyItWrites()
    {
        var key = new EllipticCurveJsonWebKey
        {
            KeyId = "kid-1",
            Usage = PublicKeyUsages.Signature,
            Algorithm = SigningAlgorithms.ES256,
            Curve = EllipticCurveTypes.P256,
            X = [1, 2],
            Y = [3, 4],
        };

        var written = JsonDocument.Parse(JsonSerializer.Serialize<JsonWebKey>(key, UpperCasingOptions)).RootElement;

        Assert.Equal(JsonWebKeyTypes.EllipticCurve, written.GetProperty("kty").GetString());
        Assert.Equal("kid-1", written.GetProperty("kid").GetString());
        Assert.Equal(PublicKeyUsages.Signature, written.GetProperty("use").GetString());
        Assert.Equal(SigningAlgorithms.ES256, written.GetProperty("alg").GetString());
        Assert.Equal(EllipticCurveTypes.P256, written.GetProperty("crv").GetString());
    }

    [Fact]
    public void AHostStringConverter_DoesNotRewriteTheMembersOfAKeyItReads()
    {
        const string json = """{"kty":"oct","kid":"kid-1","use":"sig","alg":"HS256","k":"AQID"}""";

        var key = Assert.IsType<OctetJsonWebKey>(JsonSerializer.Deserialize<JsonWebKey>(json, UpperCasingOptions));

        Assert.Equal("kid-1", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.HS256, key.Algorithm);
    }

    [Fact]
    public void AMemberNamedInAnotherCase_IsNotReadAsThatMember()
    {
        const string json = """{"kty":"oct","KID":"abc","USE":"sig","k":"AQID"}""";

        var key = JsonSerializer.Deserialize<JsonWebKey>(json, WebOptions);

        Assert.NotNull(key);
        Assert.Null(key.KeyId);
        Assert.Null(key.Usage);
    }

    [Fact]
    public void AMemberNamedInTwoCases_IsReadInItsOwnCase()
    {
        const string json = """{"kty":"oct","kid":"a","KID":"b","k":"AQID"}""";

        var key = JsonSerializer.Deserialize<JsonWebKey>(json, WebOptions);

        Assert.Equal("a", key?.KeyId);
    }

    /// <summary>
    /// RFC 7517 section 4 lets a parser either refuse a duplicate member name or take its last value; refusing
    /// leaves no two parties reading one key differently.
    /// </summary>
    [Theory]
    [InlineData("""{"kty":"oct","kid":"a","kid":"b","k":"AQID"}""")]
    [InlineData("""{"kty":"oct","kty":"RSA","k":"AQID"}""")]
    public void AKeyNamingAMemberTwice_IsRefused(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKey>(json, WebOptions));
    }

    [Fact]
    public void AKeySetNamedInAnotherCase_HoldsNoKeys()
    {
        const string json = """{"KEYS":[{"kty":"oct","kid":"a","k":"AQID"}]}""";

        var set = JsonSerializer.Deserialize<JsonWebKeySet>(json, WebOptions);

        Assert.NotNull(set);
        Assert.Null(set.Keys);
    }

    /// <summary>
    /// RFC 7517 section 5 holds a JWK Set to the same rule as a key.
    /// </summary>
    [Fact]
    public void AKeySetNamingItsKeysTwice_IsRefused()
    {
        const string json = """{"keys":[],"keys":[{"kty":"oct","kid":"a","k":"AQID"}]}""";

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKeySet>(json, WebOptions));
    }

    [Fact]
    public void AKeySet_IsWrittenWithItsOwnMemberName_WhateverTheHostsNamingPolicy()
    {
        var set = new JsonWebKeySet([new OctetJsonWebKey { KeyId = "a", KeyValue = [1, 2, 3] }]);
        var options = new JsonSerializerOptions(UpperCasingOptions)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseUpper,
        };

        var written = JsonDocument.Parse(JsonSerializer.Serialize(set, options)).RootElement;

        Assert.Equal("a", Assert.Single(written.GetProperty("keys").EnumerateArray()).GetProperty("kid").GetString());
    }

    private sealed class UpperCasingStringConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetString()?.ToUpperInvariant();

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
            => writer.WriteStringValue(value.ToUpperInvariant());
    }
}
