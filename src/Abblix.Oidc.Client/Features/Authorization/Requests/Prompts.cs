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


namespace Abblix.Oidc.Client.Features.Authorization.Requests;

/// <summary>
/// The values of the <c>prompt</c> parameter this client sends, named as on the wire.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0 section 3.1.2.1 defines the full set. Only the one this client sends is named
/// here; the others describe interaction a server-side library has no reason to ask for on the host's
/// behalf.
/// </remarks>
public static class Prompts
{
    /// <summary>
    /// The provider must not display any interface, and answers from the session it already has or refuses.
    /// </summary>
    /// <remarks>
    /// The one value that does not combine. OIDC Core 1.0 section 3.1.2.1: if the parameter "contains none
    /// with any other value, an error is returned" - which stands to reason, since every other value asks
    /// the provider to show something.
    /// </remarks>
    public const string None = "none";

    /// <summary>
    /// The provider must authenticate the end user again, even if a session is already established.
    /// </summary>
    /// <remarks>
    /// Not the same as <see cref="AuthorizationRequestParameters.MaxAge"/>, which asks how recent the
    /// existing authentication must be and leaves the provider to decide whether it qualifies. This demands
    /// a fresh one outright.
    /// </remarks>
    public const string Login = "login";

    /// <summary>
    /// The provider must ask the end user to consent again before returning to this client.
    /// </summary>
    public const string Consent = "consent";

    /// <summary>
    /// The provider must let the end user pick an account, rather than continuing with the current one.
    /// </summary>
    public const string SelectAccount = "select_account";
}
