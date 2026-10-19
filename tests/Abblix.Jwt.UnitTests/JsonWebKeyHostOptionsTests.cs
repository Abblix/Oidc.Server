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
    /// A host that rewrites every string it serializes.
    /// </summary>
    private static readonly JsonSerializerOptions MarkingOptions = new()
    {
        Converters = { new MarkingStringConverter() },
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

        var written = JsonDocument.Parse(JsonSerializer.Serialize<JsonWebKey>(key, MarkingOptions)).RootElement;

        Assert.Equal(JsonWebKeyTypes.EllipticCurve, written.GetProperty("kty").GetString());
        Assert.Equal("kid-1", written.GetProperty("kid").GetString());
        Assert.Equal(PublicKeyUsages.Signature, written.GetProperty("use").GetString());
        Assert.Equal(SigningAlgorithms.ES256, written.GetProperty("alg").GetString());
        Assert.Equal(EllipticCurveTypes.P256, written.GetProperty("crv").GetString());
    }

    [Fact]
    public void AHostStringConverter_DoesNotRewriteTheMembersOfAKeyItReads()
    {
        const string json = """{"kty":"EC","kid":"kid-1","use":"sig","alg":"ES256","crv":"P-256","x":"AQ","y":"Ag"}""";

        var key = Assert.IsType<EllipticCurveJsonWebKey>(JsonSerializer.Deserialize<JsonWebKey>(json, MarkingOptions));

        Assert.Equal(EllipticCurveTypes.P256, key.Curve);
        Assert.Equal("kid-1", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.ES256, key.Algorithm);
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

    /// <summary>
    /// A set naming its keys in another case has no keys member, and holds no keys, as its type says, rather than a
    /// null array a caller would enumerate.
    /// </summary>
    [Theory]
    [InlineData("""{"KEYS":[{"kty":"oct","kid":"a","k":"AQID"}]}""")]
    [InlineData("""{}""")]
    public void AKeySetWithoutItsKeysMember_HoldsNoKeys(string json)
    {
        var set = JsonSerializer.Deserialize<JsonWebKeySet>(json, WebOptions);

        Assert.NotNull(set);
        Assert.Empty(set.Keys);
    }

    /// <summary>
    /// RFC 7517 section 5 holds a JWK Set to the same rule as a key, for its keys member and for one it does not
    /// know alike.
    /// </summary>
    [Theory]
    [InlineData("""{"keys":[],"keys":[{"kty":"oct","kid":"a","k":"AQID"}]}""")]
    [InlineData("""{"keys":[],"x":1,"x":2}""")]
    public void AKeySetNamingAMemberTwice_IsRefused(string json)
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKeySet>(json, WebOptions));
    }

    [Fact]
    public void AKeySet_IsWrittenAsKeys_WhateverTheHostsNamingPolicy()
    {
        var set = new JsonWebKeySet([new OctetJsonWebKey { KeyId = "a", KeyValue = [1, 2, 3] }]);
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseUpper };

        var written = JsonDocument.Parse(JsonSerializer.Serialize(set, options)).RootElement;

        Assert.Equal("a", Assert.Single(written.GetProperty("keys").EnumerateArray()).GetProperty("kid").GetString());
    }

    /// <summary>
    /// A host that registers the set converter among its own converters still reads and writes a set.
    /// </summary>
    [Fact]
    public void AKeySet_RoundTrips_WhenTheHostRegistersTheConverterItself()
    {
        var hostOptions = new JsonSerializerOptions { Converters = { new JsonWebKeySetConverter() } };
        var set = new JsonWebKeySet([new OctetJsonWebKey { KeyId = "a", KeyValue = [1, 2, 3] }]);

        var read = JsonSerializer.Deserialize<JsonWebKeySet>(JsonSerializer.Serialize(set, hostOptions), hostOptions);

        Assert.Equal("a", Assert.Single(read!.Keys).KeyId);
    }

    private sealed class MarkingStringConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetString() + "~host";

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
            => writer.WriteStringValue(value + "~host");
    }
}
