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

namespace Abblix.Oidc.Client.Features.Authorization.Context;

/// <summary>
/// What the client must remember between sending the user to the provider and getting them back.
/// </summary>
/// <remarks>
/// The authorization response arrives on a separate request, from the user's browser, carrying only what the
/// provider chose to echo. Everything the client needs in order to judge that response therefore has to be
/// put aside beforehand, and this is that set.
/// </remarks>
public sealed record AuthorizationContext
{
    /// <summary>
    /// The opaque value sent as <c>state</c> and echoed by the provider. It identifies which request the
    /// response belongs to, and a response carrying a value that was never issued is a forged callback.
    /// </summary>
    /// <remarks>
    /// Note the limit of what it establishes, because the converse does not follow: a value that WAS
    /// issued tells the client which login the response belongs to, not whose browser it arrived in.
    /// Binding it to a browser is a separate job and is the store's, not this value's - see the remarks
    /// on <see cref="InMemoryAuthorizationStateStore"/> for what the default one does and does not do.
    /// </remarks>
    public required string State { get; init; }

    /// <summary>
    /// The value sent as <c>nonce</c> and returned inside the <c>id_token</c>, which ties that token to this
    /// request and rejects one replayed from another.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The secret half of the PKCE pair, presented when the authorization code is exchanged.
    /// </summary>
    public required string CodeVerifier { get; init; }

    /// <summary>
    /// The address the user was heading to before sign-in was required, always relative to this
    /// application.
    /// </summary>
    /// <remarks>
    /// This is the one member of this record meant to reach a redirect, and it is the one that came
    /// from the user agent - typically a "?returnUrl=" on the request that triggered the login. It is
    /// safe to redirect to only because it was refused unless relative when the state was built, which
    /// is what keeps this client from working as an open redirector (RFC 6749 section 10.15, RFC 9700
    /// section 4.11). Anything that populates this record from somewhere other than
    /// <c>AuthorizationRequestBuilder</c> owes the same check.
    /// </remarks>
    public required string ReturnUri { get; init; }

    /// <summary>
    /// The issuer this request was addressed to, so the response can be checked against the provider that was
    /// actually asked (RFC 9207).
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The redirect address sent with the request, which must be repeated verbatim when the code is
    /// exchanged.
    /// </summary>
    public required string RedirectUri { get; init; }
}
