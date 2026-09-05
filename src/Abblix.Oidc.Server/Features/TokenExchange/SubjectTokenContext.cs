// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Grants;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// The portable state extracted by an <see cref="ISubjectTokenResolver"/> from a wire-level
/// <c>subject_token</c>. Independent of the token's on-wire format -- JWT-based resolvers parse
/// the payload, opaque-token resolvers recover the equivalent fields from a previously stored
/// grant. The <see cref="TokenExchangeGrantHandler"/> consumes this record to
/// synthesise the new <see cref="AuthorizationContext"/> and
/// <see cref="UserAuthentication.AuthSession"/>.
/// </summary>
/// <param name="Subject">The end-user identifier the subject_token represents (RFC 7519 <c>sub</c>
/// claim or its opaque-token equivalent). Required.</param>
/// <param name="Issuer">The party that issued the subject_token, used as the
/// <c>IdentityProvider</c> on the synthesised <c>AuthSession</c>. <c>null</c> when the resolver
/// cannot determine it (e.g. opaque tokens without an issuer field).</param>
/// <param name="Scope">Scopes the subject_token was granted. The grant handler intersects this
/// with any <c>scope</c> the client supplied in the exchange request (RFC 8693 §2.1 narrow
/// only -- never widen). <c>null</c> when the subject_token did not carry a scope claim.</param>
/// <param name="AuthorizationDetails">RFC 9396 <c>authorization_details</c> attached to the
/// subject_token, raw <see cref="JsonArray"/> so the byte-exact payload survives the exchange
/// into the issued token. <c>null</c> when the subject_token did not carry AD.</param>
public sealed record SubjectTokenContext(
    string Subject,
    string? Issuer,
    string[]? Scope,
    JsonArray? AuthorizationDetails)
{
    /// <summary>RFC 8693 §4.1 <c>act</c> claim attached to the subject_token, captured as
    /// a raw <see cref="JsonObject"/>. When the exchange adds a new actor on top of a subject_token
    /// that already had its own act chain, the grant handler nests this value under the new actor's
    /// <c>act</c> member so the full delegation chain is preserved. <c>null</c> when the
    /// subject_token was not itself a delegation token.</summary>
    public JsonObject? Act { get; init; }

    /// <summary>
    /// The <c>client_id</c> the subject_token was originally issued to. The grant handler uses this
    /// to detect cross-client exchange attempts (Client B presenting a token issued to Client A),
    /// which is rejected by default to prevent a confused-deputy escalation. <c>null</c> when the
    /// resolver cannot determine the original client (e.g. opaque tokens without a client_id field
    /// or pre-cross-client-check tokens).
    /// </summary>
    public string? OriginalClientId { get; init; }

    /// <summary>
    /// For JWT-formatted subject_tokens, the value of the JWS <c>typ</c> header (e.g. <c>at+jwt</c>,
    /// <c>id+jwt</c>, <c>rt+jwt</c>). The grant handler uses this to detect cross-type confusion --
    /// a JWT minted as an id_token presented under <c>subject_token_type=access_token</c> is
    /// rejected even though both pass signature validation. <c>null</c> when the subject_token is
    /// not a JWT or the typ header was absent.
    /// </summary>
    public string? JwtTokenType { get; init; }
}
