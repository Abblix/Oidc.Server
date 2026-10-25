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

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// The names of the CIBA authentication request parameters, as they appear on the wire.
/// </summary>
/// <remarks>
/// Named constants rather than literals for the same reason claim names are: a typo in a literal produces a
/// request the provider rejects for a reason that reads like anything but a typo.
/// </remarks>
public static class Parameters
{
    /// <summary>What the eventual tokens are to be good for. Must include <c>openid</c>.</summary>
    public const string Scope = "scope";

    /// <summary>A hint the provider can resolve to a person.</summary>
    public const string LoginHint = "login_hint";

    /// <summary>The same, in a form the provider issued and can verify.</summary>
    public const string LoginHintToken = "login_hint_token";

    /// <summary>An ID Token this provider issued earlier, naming the person to ask.</summary>
    public const string IdTokenHint = "id_token_hint";

    /// <summary>A short message shown to the person, so they can tell which request they are approving.</summary>
    public const string BindingMessage = "binding_message";

    /// <summary>A secret the person knows and the provider can check.</summary>
    public const string UserCode = "user_code";

    /// <summary>The authentication assurance being asked for.</summary>
    public const string AcrValues = "acr_values";

    /// <summary>How long the client would like the request to stay open, in seconds.</summary>
    public const string RequestedExpiry = "requested_expiry";
}
