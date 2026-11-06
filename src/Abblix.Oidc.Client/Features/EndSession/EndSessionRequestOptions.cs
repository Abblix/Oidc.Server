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

namespace Abblix.Oidc.Client.Features.EndSession;

/// <summary>
/// Configuration of the logout requests this client sends to the provider.
/// </summary>
public sealed class EndSessionRequestOptions
{
    /// <summary>
    /// Where the provider is asked to send the user once the logout is done.
    /// </summary>
    /// <remarks>
    /// Absolute, for the same reason the redirection endpoint is: the provider hands this address to the
    /// browser, which resolves it from the page it is standing on - the provider's own. A relative value
    /// therefore points back into the provider's site, and the user never returns here.
    /// OpenID Connect RP-Initiated Logout 1.0 section 2 adds that "the value MUST have been previously
    /// registered with the OP, either using the post_logout_redirect_uris Registration parameter or via
    /// another mechanism", so it is configured once here rather than taken from a caller: an unregistered
    /// address is refused by the provider, and a caller-supplied one would be an open redirect waiting for
    /// a provider that does not check.
    /// </remarks>
    public Uri? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// The languages the end-user prefers for the provider's own logout pages, most preferred first.
    /// </summary>
    /// <remarks>
    /// Sent as the space-separated list of BCP 47 tags that OpenID Connect RP-Initiated Logout 1.0 section 2
    /// defines for <c>ui_locales</c>.
    /// </remarks>
    public IList<string> UiLocales { get; } = [];
}
