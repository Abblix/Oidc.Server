// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Signs the discovery document with one of this provider's own signing keys, per RFC 8414 section 2.1.
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
    /// Serializes the metadata into the <c>signed_metadata</c> JWS payload. The members of the metadata leave
    /// themselves out when null, so the signed copy omits what the plain JSON omits, and RFC 8414 section 2.1
    /// "signed values take precedence" cannot assert a null onto clients.
    /// </summary>
    private static readonly JsonSerializerOptions SerializerOptions = new();

    /// <inheritdoc />
    public async Task<string> SignAsync(TenantDefinition tenant, Model.ConfigurationResponse metadata)
    {
        var signingKeys = await serviceKeysProvider.GetSigningKeys(tenant, true).ToArrayAsync();
        if (signingKeys.Length == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(DiscoveryOptions)}.{nameof(DiscoveryOptions.SignedMetadata)} is enabled but no signing keys are configured. " +
                "Configure signing certificates so the discovery document can be signed (RFC 8414 section 2.1).");
        }

        // FAPI 1.0 Part 2 section 8.6, FAPI 2.0 section 5.4.1: a JWS this server creates uses only the algorithms the
        // profile the tenant holds its clients to admits, so the first key signing with one of them is taken
        // Without such a profile the first key signs, and a key whose algorithm cannot be named is said so; under one
        // a key that cannot be named, or names an algorithm the profile does not admit, is passed over for the next
        var profile = SecurityProfileRequirements.Resolve(tenant.DefaultSecurityProfile);
        var (signingKey, algorithm) = profile.RequireFapiSigningAlgorithms
            ? signingKeys
                .Select(key => (Key: key, Algorithm: NamedAlgorithmFor(key, profile)))
                .FirstOrDefault(candidate => candidate.Algorithm is { } named && profile.PermitsSigningAlgorithm(named))
            : (signingKeys[0], SigningAlgorithmFor(signingKeys[0], profile));
        if (signingKey is null || algorithm is null)
        {
            throw new InvalidOperationException(
                "No signing key of this tenant signs with an algorithm its security profile admits, so the discovery " +
                $"document cannot be signed; add a key for {string.Join(" or ", SecurityProfileRequirements.FapiSigningAlgorithms)}.");
        }

        var payload = JsonSerializer.SerializeToNode(metadata, SerializerOptions) switch
        {
            JsonObject jsonObject => jsonObject,

            _ => throw new InvalidOperationException(
                "Discovery metadata serialized to a non-object JSON node. The metadata must serialize to a JSON object so it " +
                "can form the signed_metadata JWS payload (RFC 8414 section 2.1); " +
                "a different node kind indicates a broken serializer or type-info resolver."),
        };

        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm },
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
    /// RFC 7517 section 4.4 makes <c>alg</c> OPTIONAL on a key, and the rest of this server honors that - a key
    /// declaring no algorithm is usable with any compatible one (see
    /// <c>JsonWebKeyExtensions.FirstByAlgorithmAsync</c>). Reading the algorithm straight off the key
    /// inverted that rule here, and since a key imported from an RSA certificate declares none, every such
    /// deployment answered its discovery endpoint with an error once signed metadata was switched on.
    /// The fallback for elliptic-curve keys follows the curve, the same pairing
    /// <c>EllipticCurveJsonWebKeyExtensions.Apply</c> uses when it imports one.
    /// </remarks>
    private static string SigningAlgorithmFor(JsonWebKey signingKey, SecurityProfileRequirements profile)
        => NamedAlgorithmFor(signingKey, profile) ?? throw new InvalidOperationException(
            signingKey is EllipticCurveJsonWebKey { Curve: var curve }
                ? $"The signing key names the curve '{curve}', which this server has no signing algorithm for. Set " +
                  "the alg parameter on the key to say how the discovery document is to be signed (RFC 7517 section 4.4)."
                : $"The signing key is a {signingKey.GetType().Name} and declares no alg parameter, so there is no " +
                  "algorithm to sign the discovery document with. Set the alg parameter on the key (RFC 7517 section 4.4).");

    /// <summary>
    /// The algorithm the key signs with: the one it declares, else the one its material implies, or null where neither
    /// names one.
    /// </summary>
    private static string? NamedAlgorithmFor(JsonWebKey signingKey, SecurityProfileRequirements profile)
    {
        if (signingKey.Algorithm is { } declared)
            return declared;

        return signingKey switch
        {
            // RSASSA-PSS where the profile admits no PKCS #1 v1.5 signature, RS256 otherwise
            RsaJsonWebKey when profile.RequireFapiSigningAlgorithms => SigningAlgorithms.PS256,
            RsaJsonWebKey => SigningAlgorithms.RS256,

            EllipticCurveJsonWebKey { Curve: var curve } => curve switch
            {
                EllipticCurveTypes.P256 => SigningAlgorithms.ES256,
                EllipticCurveTypes.P384 => SigningAlgorithms.ES384,
                EllipticCurveTypes.P521 => SigningAlgorithms.ES512,
                _ => null,
            },

            _ => null,
        };
    }
}
