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
/// What a front-channel logout request says, once it has been read.
/// </summary>
/// <remarks>
/// Deliberately thinner than its back-channel counterpart, and it is worth being plain about why. A
/// front-channel logout arrives as a browser loading an image-sized frame; there is no token, nothing is
/// signed, and the only thing distinguishing it from any other page a browser was told to load is the
/// address it was sent to. It says a session ended. It does not prove one did.
/// So this is a hint to act on, not a statement to trust, and what a host may safely do with it is end its
/// own local session - which costs the user a sign-in at worst. Anything with a consequence beyond that
/// belongs behind the back channel, where a signed token says who is asking.
/// </remarks>
/// <param name="Issuer">
/// The provider the request claims to come from, from the <c>iss</c> query parameter, when it carried one.
/// </param>
/// <param name="SessionId">
/// The session the request says has ended, from the <c>sid</c> query parameter, when it carried one.
/// </param>
public sealed record FrontChannelLogoutNotification(string? Issuer, string? SessionId);
