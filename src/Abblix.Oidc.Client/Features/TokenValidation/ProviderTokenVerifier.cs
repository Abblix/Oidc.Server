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
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.SigningKeys;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.TokenValidation;

/// <summary>
/// Verifies tokens the provider signed for this client.
/// </summary>
/// <param name="tokenValidator">Verifies the signature and the JWT-level claims.</param>
/// <param name="metadataProvider">Supplies the issuer this client is talking to.</param>
/// <param name="signingKeysProvider">Supplies the provider's keys.</param>
/// <param name="clientOptions">Carries the client identifier that <c>aud</c> is matched against.</param>
/// <param name="options">Where the specification leaves a policy choice.</param>
public sealed class ProviderTokenVerifier(
    IJsonWebTokenValidator tokenValidator,
    IProviderMetadataProvider metadataProvider,
    IIssuerSigningKeysProvider signingKeysProvider,
    IOptions<OidcClientOptions> clientOptions,
    IOptions<ProviderTokenValidationOptions> options) : IProviderTokenVerifier
{
    /// <inheritdoc />
    public async Task<JsonWebToken> VerifyAsync(
        string token, CancellationToken cancellationToken = default)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);
        var clientId = clientOptions.Value.ClientId;
        var policy = options.Value;

        var parameters = new ValidationParameters
        {
            Options = ValidationOptions.Default,

            // OIDC Core 1.0 section 3.1.3.7 step 2: "The Issuer Identifier for the OpenID Provider ... MUST
            // exactly match the value of the iss (issuer) Claim." Exactly, so an ordinal comparison and no
            // normalisation - a trailing slash makes a different issuer, not a forgiving one.
            ValidateIssuer = tokenIssuer => Task.FromResult(
                string.Equals(tokenIssuer, metadata.Issuer, StringComparison.Ordinal)),

            // Step 3: the aud Claim MUST contain this client as an audience, and the token MUST be rejected
            // "if the ID Token does not list the Client as a valid audience, or if it contains additional
            // audiences not trusted by the Client". This client trusts none but itself, so a second audience
            // is a rejection rather than something to look past: a token minted for two parties is one the
            // other party can replay here.
            ValidateAudience = audiences => Task.FromResult(IsSoleAudience(audiences, clientId)),

            // Step 6 permits skipping signature validation when the token came straight from the token
            // endpoint over TLS. This client declines that permission: the transport authenticates the
            // channel, not the token, and the same code path also carries tokens that arrived through a
            // browser or, for a Logout Token, from a caller this client never spoke to first. One rule,
            // applied everywhere, is the one that cannot be applied to the wrong delivery by mistake.
            ResolveIssuerSigningKeys = _ => ResolveKeys(cancellationToken),

            AllowedSigningAlgorithms = policy.AllowedSigningAlgorithms.ToHashSet(StringComparer.Ordinal),
            ClockSkew = policy.ClockSkew,
        };

        var result = await tokenValidator.ValidateAsync(token, parameters);
        if (result.TryGetFailure(out var error))
            throw new ProviderTokenValidationException($"The token was rejected: {error.ErrorDescription}");

        return result.GetSuccess();
    }

    /// <summary>
    /// Reports whether <paramref name="clientId"/> is the one and only audience.
    /// </summary>
    /// <remarks>
    /// Two conditions from OIDC Core 1.0 section 3.1.3.7 step 3 collapse into one predicate: this client
    /// must be listed, and no audience it does not trust may be. It trusts only itself, so anything beyond a
    /// single matching entry fails - including a repeated one, since a token naming this client twice is
    /// malformed rather than doubly addressed.
    /// </remarks>
    private static bool IsSoleAudience(IEnumerable<string> audiences, string clientId)
    {
        using var enumerator = audiences.GetEnumerator();

        return enumerator.MoveNext()
               && string.Equals(enumerator.Current, clientId, StringComparison.Ordinal)
               && !enumerator.MoveNext();
    }

    /// <summary>
    /// Reads the provider's keys. The token's own <c>kid</c> is not consulted here because the validator has
    /// not parsed it yet at this point; the provider returns every held key and the signature check tries
    /// them.
    /// </summary>
    private async IAsyncEnumerable<JsonWebKey> ResolveKeys(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var keys = await signingKeysProvider.GetSigningKeysAsync(keyId: null, cancellationToken);
        foreach (var key in keys)
            yield return key;
    }
}
