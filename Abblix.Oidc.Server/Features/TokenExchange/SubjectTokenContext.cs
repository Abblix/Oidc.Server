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

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// The portable state extracted by an <see cref="ISubjectTokenResolver"/> from a wire-level
/// <c>subject_token</c>. Independent of the token's on-wire format -- JWT-based resolvers parse
/// the payload, opaque-token resolvers recover the equivalent fields from a previously stored
/// grant. The <see cref="TokenExchange.TokenExchangeGrantHandler"/> consumes this record to
/// synthesise the new <see cref="Endpoints.Authorization.AuthorizationContext"/> and
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
/// <param name="AuthorizationDetailsRaw">RFC 9396 <c>authorization_details</c> attached to the
/// subject_token, raw <see cref="JsonArray"/> so the byte-exact payload survives the exchange
/// into the issued token. <c>null</c> when the subject_token did not carry AD.</param>
public sealed record SubjectTokenContext(
    string Subject,
    string? Issuer,
    string[]? Scope,
    JsonArray? AuthorizationDetailsRaw);
