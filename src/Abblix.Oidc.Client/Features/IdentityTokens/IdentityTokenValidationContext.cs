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

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// What this client sent, and what arrived beside the ID Token, so the validator can check the
/// answer against the question rather than against itself.
/// </summary>
/// <remarks>
/// Most of what makes ID Token validation meaningful is not in the token. A nonce proves the token
/// answers this login only if the client remembers which nonce it sent; <c>at_hash</c> binds an
/// access token only if the client has that access token to hash; <c>max_age</c> makes
/// <c>auth_time</c> checkable only if the client knows it asked. A validator handed the token alone
/// can verify a signature and some claim shapes, and would call a perfectly replayed token from a
/// different login valid.
/// Every member is per-call data. Nothing here is a service - the validator injects those.
/// </remarks>
public sealed record IdentityTokenValidationContext
{
    /// <summary>
    /// The nonce this client sent on the authorization request, or <see langword="null"/> when it sent none.
    /// </summary>
    /// <remarks>
    /// Null and "the token has no nonce" are different situations and are treated differently: a client
    /// that sent a nonce requires a matching one back, while a client that sent none has nothing to
    /// compare against. Silence in both directions is the only combination that passes without a check.
    /// </remarks>
    public string? Nonce { get; init; }

    /// <summary>
    /// The authorization code that arrived with this ID Token, when it came from the authorization
    /// endpoint. Supplying it turns on the <c>c_hash</c> check.
    /// </summary>
    public string? AuthorizationCode { get; init; }

    /// <summary>
    /// The access token that arrived with this ID Token. Supplying it turns on the <c>at_hash</c> check.
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// The <c>max_age</c> this client sent, if any. Its presence is what obliges the provider to state
    /// <c>auth_time</c>, and what gives the client something to measure that claim against.
    /// </summary>
    public TimeSpan? MaxAge { get; init; }

    /// <summary>
    /// The authentication context class values this client is willing to accept, when it asked for any.
    /// Empty means it did not ask, and the <c>acr</c> claim is then not this client's business.
    /// </summary>
    public IReadOnlyCollection<string> AcceptableAuthenticationContextClassReferences { get; init; } = [];
}
