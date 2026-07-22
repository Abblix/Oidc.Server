// Abblix OIDC Client Library
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

using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.TokenValidation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Requires the provider's metadata to carry an RFC 8414 section 2.1 <c>signed_metadata</c> value, verifies
/// it against keys the host holds, and lets the signed values take precedence over the published JSON.
/// </summary>
/// <remarks>
/// The keys come from the host rather than from <c>jwks_uri</c>, and that is the whole point of the feature.
/// A signature verified with a key the document itself names proves only that whoever wrote the document also
/// wrote the key set, which is no more than the document already claims. Keys held out of band turn the
/// signature into evidence about who produced the document, which is the assurance a host asks for when it
/// cannot rely on the transport alone: metadata that reached it through a registry, a mirror, a cache, or a
/// TLS-terminating intermediary it does not own.
///
/// Because that is what the host asked for, a document arriving without <c>signed_metadata</c> is refused
/// rather than accepted on its plain values. Accepting it would let anyone able to strip one member downgrade
/// the deployment to the assurance it deliberately moved away from.
///
/// One narrowing of the specification is deliberate and worth naming: section 2.1 says the <c>iss</c> claim
/// denotes "the party attesting to the claims in the signed metadata", which permits a third party to attest
/// for a provider. This client requires the attesting party to be the provider the effective document names.
/// Delegated attestation needs a way to decide which third parties may speak for which issuers, and that is
/// what a federation profile defines; inventing one here would be a trust model of our own making.
/// </remarks>
/// <param name="tokenValidator">Verifies the JWS.</param>
/// <param name="verificationKeys">The keys the host holds for the provider's metadata.</param>
/// <param name="options">Supplies the signing algorithms this client accepts from its provider.</param>
public sealed class SignedMetadataVerifier(
    IJsonWebTokenValidator tokenValidator,
    IReadOnlyCollection<JsonWebKey> verificationKeys,
    IOptions<ProviderTokenValidationOptions> options) : ISignedMetadataVerifier
{
    /// <summary>
    /// The member carrying the signed bundle, per RFC 8414 section 2.1.
    /// </summary>
    private const string SignedMetadataMember = "signed_metadata";

    /// <summary>
    /// The member naming the provider, per RFC 8414 section 2.
    /// </summary>
    private const string IssuerMember = "issuer";

    /// <inheritdoc />
    public async Task<JsonObject> ApplyAsync(
        JsonObject document, CancellationToken cancellationToken = default)
    {
        if (!document.TryGetPropertyValue(SignedMetadataMember, out var signedMetadata))
            throw new ProviderMetadataException(
                "The OpenID Provider metadata carries no signed_metadata, and this client is configured to "
                + "act only on metadata it can verify against the keys it holds.");

        if (signedMetadata?.GetValueKind() is not System.Text.Json.JsonValueKind.String)
            throw new ProviderMetadataException(
                "The signed_metadata member of the OpenID Provider metadata is not a string, so it is not "
                + "the JWS that RFC 8414 section 2.1 defines.");

        var payload = await VerifyAsync(signedMetadata.GetValue<string>(), cancellationToken);
        var effective = Merge(document, payload.Json);

        // RFC 8414 section 2.1 requires the iss claim to name the party attesting to the bundle. Compared
        // against the effective issuer rather than the published one, so a bundle that restates the issuer
        // is checked against what it restated it to: otherwise a document could be signed for one provider
        // and carry the identifier of another. That value exists only after the merge, which is why the
        // presence and the comparison are made here rather than through ValidationOptions.RequireIssuer -
        // the validator pairs that flag with a delegate, and there is nothing to give it yet.
        if (payload.Issuer is null)
            throw new ProviderMetadataException(
                "The signed metadata names no attesting party, and RFC 8414 section 2.1 requires it to carry "
                + "an iss claim.");

        var effectiveIssuer = effective[IssuerMember]?.GetValue<string>();
        if (!string.Equals(payload.Issuer, effectiveIssuer, StringComparison.Ordinal))
            throw new ProviderMetadataException(
                $"The signed metadata is attested by '{payload.Issuer}', which is not the issuer "
                + $"'{effectiveIssuer}' of the metadata it attests to.");

        return effective;
    }

    private async Task<JsonWebTokenPayload> VerifyAsync(string signedMetadata, CancellationToken cancellationToken)
    {
        var parameters = new ValidationParameters
        {
            // Signature only. No audience: the bundle asserts facts about the provider rather than addressing
            // a recipient, and RFC 8414 section 2.1 names only iss. No lifetime either - the section requires
            // no exp, so demanding one would refuse every conformant provider; the document's freshness is
            // bounded by how long the client caches it, not by a claim the specification never asked for.
            // The iss claim is required, and checked by the caller once there is an issuer to check it
            // against.
            Options = ValidationOptions.RequireValidSignedTokens,

            ResolveIssuerSigningKeys = _ => ReadKeys(cancellationToken),

            // The same allow-list the provider's tokens are held to. One policy, because these are the same
            // provider's signatures made with the same kind of key: a deployment that refuses an algorithm
            // for an ID Token has no reason to accept it here, and two settings would only make it possible
            // to tighten one and forget the other.
            AllowedSigningAlgorithms = options.Value.AllowedSigningAlgorithms.ToHashSet(StringComparer.Ordinal),
        };

        var result = await tokenValidator.ValidateAsync(signedMetadata, parameters);
        if (result.TryGetFailure(out var error))
            throw new ProviderMetadataException(
                $"The signed metadata of the OpenID Provider was rejected: {error.ErrorDescription}");

        return result.GetSuccess().Payload;
    }

    /// <summary>
    /// Produces the effective document: every member the bundle asserts replaces the published one, and
    /// members the bundle is silent about keep their published values.
    /// </summary>
    /// <remarks>
    /// Merged as JSON rather than as parsed metadata so that the precedence RFC 8414 section 2.1 states
    /// covers members this client does not model. A per-property merge over the modelled type would silently
    /// leave everything else at its published value, which is the opposite of what the section says, and it
    /// would go on being wrong every time a member is added to the model.
    /// </remarks>
    private static JsonObject Merge(JsonObject published, JsonObject signed)
    {
        var effective = published.DeepClone().AsObject();
        foreach (var (name, value) in signed)
            effective[name] = value?.DeepClone();

        return effective;
    }

    private async IAsyncEnumerable<JsonWebKey> ReadKeys(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var key in verificationKeys)
            yield return key;

        await Task.CompletedTask;
    }
}
