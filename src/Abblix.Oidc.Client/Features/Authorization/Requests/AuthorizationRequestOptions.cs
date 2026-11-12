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

using Abblix.Oidc.Client.Common;

namespace Abblix.Oidc.Client.Features.Authorization.Requests;

/// <summary>
/// Configuration of the authorization requests this client sends.
/// </summary>
public sealed class AuthorizationRequestOptions
{
    /// <summary>
    /// The absolute address the provider returns the user to. Must be one the provider has registered for
    /// this client, and is repeated verbatim when the authorization code is exchanged.
    /// </summary>
    /// <remarks>
    /// Absolute, and a relative value is refused when a request is built. The provider hands this
    /// address to the browser, and the browser resolves it from where it is standing - the provider's
    /// own page - so a relative one points back into the provider's site and the user lands there,
    /// signed in, having never reached this application. RFC 6749 section 3.1.2: "The redirection
    /// endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3."
    /// <see cref="Uri"/> holds a relative address just as happily, so the type cannot say this.
    /// </remarks>
    public required Uri RedirectUri { get; set; }

    /// <summary>
    /// Which flow this client runs, defaulting to the authorization code flow.
    /// </summary>
    /// <remarks>
    /// Every other flow returns a token through the browser and additionally requires
    /// <see cref="FrontChannelTokensAccepted"/> to be set - the flow says WHICH, the acceptance says the
    /// host has taken the risk on purpose. Two settings rather than one so that neither a mis-bound
    /// configuration value nor an over-eager default can enable a front-channel-token flow by itself.
    /// </remarks>
    public AuthorizationFlow Flow { get; set; } = AuthorizationFlow.Code;

    /// <summary>
    /// Acknowledges that this client accepts tokens returned through the browser, which
    /// <see cref="Flow"/> values other than <see cref="AuthorizationFlow.Code"/> do.
    /// </summary>
    /// <remarks>
    /// Off by default, and a token-returning flow selected without it is refused when the request is
    /// built rather than at some later point where the cause would be harder to see. A token in the front
    /// channel is exposed to the browser's history, to the referrer of anything the page loads, and to
    /// any script on it; OAuth 2.0 Security BCP (RFC 9700 section 2.1.2) is direct about the consequence -
    /// "clients SHOULD NOT use the implicit grant (response type "token") or any other response type
    /// issuing access tokens in the authorization response, such as "token id_token" and "code token
    /// id_token"".
    /// The name says what it is rather than what it enables, so that reading the configuration tells a
    /// reviewer what was accepted.
    /// </remarks>
    public bool FrontChannelTokensAccepted { get; set; }

    /// <summary>
    /// How the provider should return the response, sent as <c>response_mode</c>. Left null the parameter
    /// is omitted for the code flow, and required for any flow that returns tokens.
    /// </summary>
    /// <remarks>
    /// The code flow needs nothing here: Multiple Response Type Encoding Practices section 5 makes query
    /// its default, which is what a server-side callback reads anyway.
    /// A token-returning flow does need it, and this is the setting that decides whether the client can
    /// receive the response at all. That same section makes the fragment the default for those flows and
    /// says "the query encoding MUST NOT be used" - and a fragment, per RFC 3986 section 3.5, "is
    /// dereferenced solely by the user agent", so it never reaches a server. A server-side client must
    /// therefore ask for <see cref="ResponseModes.FormPost"/>; a browser-based client that reads the
    /// fragment itself uses <see cref="ResponseModes.Fragment"/>. The builder refuses to guess between
    /// them, because guessing wrong means a callback that arrives empty.
    /// </remarks>
    public string? ResponseMode { get; set; }

    /// <summary>
    /// The scopes requested. <c>openid</c> is what makes the request an OpenID Connect one rather than plain
    /// OAuth, so it is included by default.
    /// </summary>
    public IReadOnlyCollection<string> Scopes { get; set; } = [Common.Scopes.OpenId, Common.Scopes.Profile];

    /// <summary>
    /// The resources the issued access token is meant for, sent as <c>resource</c> per RFC 8707.
    /// </summary>
    /// <remarks>
    /// Naming them narrows the token to those resources, so a token leaked by one of them cannot be spent at
    /// another. Left empty the parameter is omitted, and the provider decides the audience itself.
    /// </remarks>
    public IReadOnlyCollection<Uri> Resources { get; set; } = [];

    /// <summary>
    /// Extra parameters appended to every authorization request, for anything a provider expects that this
    /// client does not model.
    /// </summary>
    public IReadOnlyDictionary<string, string> AdditionalParameters { get; set; } =
        new Dictionary<string, string>();
}
