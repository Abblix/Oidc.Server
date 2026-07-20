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

namespace Abblix.Oidc.Client.Features.AuthorizationRequests;

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
    /// The scopes requested. <c>openid</c> is what makes the request an OpenID Connect one rather than plain
    /// OAuth, so it is included by default.
    /// </summary>
    public IReadOnlyCollection<string> Scopes { get; set; } = ["openid", "profile"];

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
