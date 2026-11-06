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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// Why no token could be supplied.
/// </summary>
/// <remarks>
/// Carried separately from the message because a caller acts on it, and because the three causes have three
/// different fixes in three different places. Collapsed into one message they become one grep that matches
/// everything and distinguishes nothing.
/// </remarks>
public enum AccessTokenUnavailableReason
{
    /// <summary>
    /// There is no current request, so there is no signed-in user to take a token from.
    /// </summary>
    /// <remarks>
    /// What a background job sees when it uses the session-backed source. The fix is a source of its own.
    /// </remarks>
    NoAmbientSession,

    /// <summary>
    /// There is a session, but no access token was kept with it.
    /// </summary>
    /// <remarks>
    /// Almost always <c>SaveTokens</c> left off. Worth its own reason because it looks identical to
    /// "not signed in" from the outside, and is a one-line fix in a different file.
    /// </remarks>
    TokensNotStored,

    /// <summary>
    /// The token that was kept has passed its expiry.
    /// </summary>
    /// <remarks>
    /// Refused before the call rather than sent. Presenting a token known to be dead produces a 401
    /// indistinguishable from every other 401, and this library does not refresh on the host's behalf.
    /// </remarks>
    Expired,
}
