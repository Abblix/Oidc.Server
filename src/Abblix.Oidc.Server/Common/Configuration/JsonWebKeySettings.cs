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
using Abblix.Jwt;
using Abblix.Utils.Polyfills;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Flat configuration DTO for a single JSON Web Key, suitable for binding via
/// <c>Microsoft.Extensions.Configuration</c> which cannot instantiate the abstract
/// <see cref="JsonWebKey"/> base type directly. All cryptographic byte-array members
/// are bound as base64url-encoded strings per RFC 7517; <see cref="ToJsonWebKey"/>
/// decodes them and maps the flat shape to the correct concrete subtype based on
/// <see cref="Kty"/>.
/// </summary>
/// <remarks>
/// <para>
/// Design rationale: a flat DTO that mirrors the RFC 7517 wire format keeps the
/// configuration path free of <c>System.Text.Json</c> roundtrips and custom converters.
/// Every JWK member binds out-of-the-box as a nullable string, the mapper handles
/// base64url decoding and the <c>kty</c> dispatch in one place, and the schema lives as
/// explicit C# code - refactor-safe and IntelliSense-friendly. The configuration binder
/// itself produces path-aware error messages on invalid input, so operators do not have
/// to translate generic JSON exceptions back to config paths.
/// </para>
/// <para>
/// Each property carries a <see cref="ConfigurationKeyNameAttribute"/> pointing at the
/// RFC 7517 wire name from <see cref="JsonWebKeyPropertyNames"/>, so config keys can be
/// written exactly as JWK consumers expect them (<c>kty</c>, <c>n</c>, <c>e</c>, ...) and
/// the binder maps them unambiguously to the C# properties.
/// </para>
/// <para>
/// A native polymorphic binding via <c>[JsonPolymorphic]</c> + <c>[JsonDerivedType]</c>
/// was considered and rejected after empirical verification on net8.0 / net9.0 / net10.0:
/// <c>Microsoft.Extensions.Configuration.Binder</c> does not honour these
/// <c>System.Text.Json</c> attributes and still throws «Cannot create instance of
/// abstract type» on <see cref="JsonWebKey"/>. The flat DTO is the practical workaround
/// until the binder gains its own polymorphism support.
/// </para>
/// <para>
/// Adding support for a new JWK type that the RFC introduces (for example OKP per
/// RFC 8037 for Ed25519 / X25519 keys) is a fully localised change: add the new fields
/// to this DTO and a new branch in the <c>Kty</c> switch inside <see cref="ToJsonWebKey"/>.
/// No changes required in the polymorphic <see cref="JsonWebKey"/> hierarchy beyond the
/// new concrete subtype itself.
/// </para>
/// </remarks>
public sealed class JsonWebKeySettings
{
    /// <summary>Key type discriminator: <c>RSA</c>, <c>EC</c>, or <c>oct</c>.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.KeyType)]
    public string? Kty { get; init; }

    /// <summary>Key ID for selection in multi-key environments.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.KeyId)]
    public string? Kid { get; init; }

    /// <summary>Public key use: <c>sig</c> or <c>enc</c>.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.Usage)]
    public string? Use { get; init; }

    /// <summary>Algorithm intended for use with this key.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.Algorithm)]
    public string? Alg { get; init; }

    /// <summary>RSA modulus (n).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.Modulus)]
    public string? N { get; init; }

    /// <summary>RSA public exponent (e).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.Exponent)]
    public string? E { get; init; }

    /// <summary>RSA or EC private exponent / key (d).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.PrivateExponent)]
    public string? D { get; init; }

    /// <summary>RSA first prime factor (p).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.FirstPrimeFactor)]
    public string? P { get; init; }

    /// <summary>RSA second prime factor (q).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.SecondPrimeFactor)]
    public string? Q { get; init; }

    /// <summary>RSA first factor CRT exponent (dp).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.FirstFactorCrtExponent)]
    public string? Dp { get; init; }

    /// <summary>RSA second factor CRT exponent (dq).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.SecondFactorCrtExponent)]
    public string? Dq { get; init; }

    /// <summary>RSA first CRT coefficient (qi).</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.FirstCrtCoefficient)]
    public string? Qi { get; init; }

    /// <summary>EC curve identifier (crv): <c>P-256</c>, <c>P-384</c>, or <c>P-521</c>.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.Curve)]
    public string? Crv { get; init; }

    /// <summary>EC X coordinate.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.EllipticCurveX)]
    public string? X { get; init; }

    /// <summary>EC Y coordinate.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.EllipticCurveY)]
    public string? Y { get; init; }

    /// <summary>Symmetric (oct) key value.</summary>
    [ConfigurationKeyName(JsonWebKeyPropertyNames.KeyValue)]
    public string? K { get; init; }

    /// <summary>Maps this flat DTO to the corresponding concrete <see cref="JsonWebKey"/> subtype.</summary>
    /// <exception cref="InvalidOperationException"><see cref="Kty"/> is missing or not <c>RSA</c>/<c>EC</c>/<c>oct</c>.</exception>
    /// <exception cref="FormatException">A byte-array member is not valid base64url.</exception>
    public JsonWebKey ToJsonWebKey() => Kty switch
    {
        JsonWebKeyTypes.Rsa => ToRsaJsonWebKey(),
        JsonWebKeyTypes.EllipticCurve => ToEllipticCurveJsonWebKey(),
        JsonWebKeyTypes.Octet => ToOctetJsonWebKey(),

        null or "" => throw new InvalidOperationException(
            $"JsonWebKey settings require the '{nameof(Kty)}' discriminator to be set."),

        _ => throw new InvalidOperationException(
            $"Unsupported JsonWebKey type '{Kty}'. Expected one of: " +
            $"{JsonWebKeyTypes.Rsa}, {JsonWebKeyTypes.EllipticCurve}, {JsonWebKeyTypes.Octet}."),
    };

    private RsaJsonWebKey ToRsaJsonWebKey()
    {
        return new RsaJsonWebKey
        {
            KeyId = Kid,
            Usage = Use,
            Algorithm = Alg,
            Modulus = Decode(N),
            Exponent = Decode(E),
            PrivateExponent = Decode(D),
            FirstPrimeFactor = Decode(P),
            SecondPrimeFactor = Decode(Q),
            FirstFactorCrtExponent = Decode(Dp),
            SecondFactorCrtExponent = Decode(Dq),
            FirstCrtCoefficient = Decode(Qi),
        };
    }

    private EllipticCurveJsonWebKey ToEllipticCurveJsonWebKey()
    {
        return new EllipticCurveJsonWebKey
        {
            KeyId = Kid,
            Usage = Use,
            Algorithm = Alg,
            Curve = Crv,
            X = Decode(X),
            Y = Decode(Y),
            PrivateKey = Decode(D),
        };
    }

    private OctetJsonWebKey ToOctetJsonWebKey()
    {
        return new OctetJsonWebKey
        {
            KeyId = Kid,
            Usage = Use,
            Algorithm = Alg,
            KeyValue = Decode(K),
        };
    }

    /// <summary>Convenience implicit conversion to <see cref="JsonWebKey"/>;
    /// delegates to <see cref="ToJsonWebKey"/>.</summary>
    public static implicit operator JsonWebKey(JsonWebKeySettings settings)
        => settings.ToJsonWebKey();

    private static byte[]? Decode(string? value)
        => value is not null ? Base64Url.DecodeFromChars(value) : null;
}
