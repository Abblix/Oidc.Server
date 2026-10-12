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

namespace Abblix.Oidc.Client.Features.FrontChannelLogout;

/// <summary>
/// What this client requires of a front-channel logout request.
/// </summary>
public sealed class FrontChannelLogoutOptions
{
    /// <summary>
    /// Whether a request must name the issuer and the session it is about.
    /// </summary>
    /// <remarks>
    /// The client half of <c>frontchannel_logout_session_required</c>, which OpenID Connect Front-Channel
    /// Logout 1.0 section 2 describes as "Boolean value specifying whether the RP requires that iss (issuer)
    /// and sid (session ID) query parameters be included to identify the RP session with the OP when the
    /// frontchannel_logout_uri is used. If omitted, the default value is false."
    /// This setting is what the client enforces; whether the provider sends them is decided by the
    /// registration, so the two have to say the same thing. Turning it on and not registering it produces a
    /// client that refuses every logout its provider sends.
    /// It defaults to false to match the registration default, not because requiring them is a bad idea: an
    /// application that keeps one session per browser has nothing to tell apart, while one that keeps
    /// several needs to know which ended, and for it the answer is to register the requirement and set this.
    /// </remarks>
    public bool SessionRequired { get; set; }
}
