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


namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// How the access token is read out of the signed-in user's session.
/// </summary>
public sealed class SessionAccessTokenOptions
{
    /// <summary>
    /// Which authentication scheme holds the session, or <c>null</c> for the application's default.
    /// </summary>
    /// <remarks>
    /// Null rather than this library's own scheme name, and the difference matters. The OIDC handler signs
    /// the user in to its <c>SignInScheme</c> - a cookie, normally - and that is where the tokens are kept.
    /// Defaulting to the OIDC scheme would authenticate against a remote handler that holds no session, find
    /// nothing every time, and read as "SaveTokens is off" forever.
    /// A host with several cookie schemes names the one it means.
    /// </remarks>
    public string? AuthenticationScheme { get; set; }

    /// <summary>
    /// How long before a token's stated expiry it stops being offered.
    /// </summary>
    /// <remarks>
    /// A token that expires while in flight is refused by the resource server, which costs a round trip and
    /// produces a 401 that reads like any other. The margin buys the request time to arrive.
    /// </remarks>
    public TimeSpan ExpiryClockSkew { get; set; } = TimeSpan.FromSeconds(30);
}
