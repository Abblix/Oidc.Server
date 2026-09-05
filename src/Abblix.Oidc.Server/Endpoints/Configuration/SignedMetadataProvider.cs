// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Signs the discovery document with one of this provider's own signing keys, per RFC 8414 §2.1.
/// </summary>
/// <param name="jwtCreator">Issues the JWS.</param>
/// <param name="serviceKeysProvider">Supplies this provider's signing keys.</param>
/// <param name="clock">Stamps <c>iat</c>.</param>
public class SignedMetadataProvider(
    IJsonWebTokenCreator jwtCreator,
    IAuthServiceKeysProvider serviceKeysProvider,
    TimeProvider clock) : ISignedMetadataProvider
{
    /// <summary>
    /// Serializes the metadata into the <c>signed_metadata</c> JWS payload with the same null-omission
    /// semantics the wire JSON uses (see <see cref="JsonIgnoreNullsModifier"/>, wired by each adapter).
    /// Without re-attaching the modifier here the signed copy would carry <c>"field": null</c> entries the
    /// plain JSON omits, and RFC 8414 §2.1 "signed values take precedence" would then assert those nulls
    /// onto clients.
    /// </summary>
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver().WithAddedModifier(JsonIgnoreNullsModifier.Apply),
    };

    /// <inheritdoc />
    public async Task<string> SignAsync(Model.ConfigurationResponse metadata)
    {
        var signingKey = await serviceKeysProvider.GetSigningKeys(true).FirstOrDefaultAsync();
        if (signingKey is null)
        {
            throw new InvalidOperationException(
                $"{nameof(DiscoveryOptions)}.{nameof(DiscoveryOptions.SignedMetadata)} is enabled but no signing keys are configured. " +
                "Configure signing certificates so the discovery document can be signed (RFC 8414 §2.1).");
        }

        var payload = JsonSerializer.SerializeToNode(metadata, SerializerOptions) switch
        {
            JsonObject jsonObject => jsonObject,

            _ => throw new InvalidOperationException(
                "Discovery metadata serialized to a non-object JSON node. The metadata must serialize to a JSON object so it " +
                "can form the signed_metadata JWS payload (RFC 8414 §2.1); " +
                "a different node kind indicates a broken serializer or type-info resolver."),
        };

        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithmFor(signingKey) },
            Payload = new JsonWebTokenPayload(payload)
            {
                Issuer = metadata.Issuer,
                IssuedAt = clock.GetUtcNow(),
            },
        };

        // No encryption key is passed, so the result is always a pure JWS: a deployment that also issues JWE
        // access tokens must not turn this into a JWE, which no client could verify against jwks_uri.
        return await jwtCreator.IssueAsync(token, signingKey);
    }

    /// <summary>
    /// Names the algorithm to sign with: the one the key declares, or the standard one for its kind.
    /// </summary>
    /// <remarks>
    /// RFC 7517 §4.4 makes <c>alg</c> OPTIONAL on a key, and the rest of this server honours that - a key
    /// declaring no algorithm is usable with any compatible one (see
    /// <c>JsonWebKeyExtensions.FirstByAlgorithmAsync</c>). Reading the algorithm straight off the key
    /// inverted that rule here, and since a key imported from an RSA certificate declares none, every such
    /// deployment answered its discovery endpoint with an error once signed metadata was switched on.
    /// The fallback for elliptic-curve keys follows the curve, the same pairing
    /// <c>JsonWebKeyExtensions.Apply</c> uses when it imports one.
    /// </remarks>
    private static string SigningAlgorithmFor(JsonWebKey signingKey)
    {
        if (signingKey.Algorithm is { } declared)
            return declared;

        return signingKey switch
        {
            RsaJsonWebKey => SigningAlgorithms.RS256,

            EllipticCurveJsonWebKey { Curve: var curve } => curve switch
            {
                EllipticCurveTypes.P256 => SigningAlgorithms.ES256,
                EllipticCurveTypes.P384 => SigningAlgorithms.ES384,
                EllipticCurveTypes.P521 => SigningAlgorithms.ES512,

                _ => throw new InvalidOperationException(
                    $"The signing key names the curve '{curve}', which this server has no signing algorithm "
                    + "for. Set the alg parameter on the key to say how the discovery document is to be "
                    + "signed (RFC 7517 section 4.4)."),
            },

            _ => throw new InvalidOperationException(
                $"The signing key is a {signingKey.GetType().Name} and declares no alg parameter, so there "
                + "is no algorithm to sign the discovery document with. Set the alg parameter on the key "
                + "(RFC 7517 section 4.4)."),
        };
    }
}
