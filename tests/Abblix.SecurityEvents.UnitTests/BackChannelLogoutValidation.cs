// Abblix OIDC Server Library
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

using Abblix.Jwt;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Names the Back-Channel Logout receiver's validation profile, as
/// <c>Abblix.SharedSignals.Receiver.SsfReceiverValidation</c> names the Shared Signals one:
/// whoever creates, edits and resolves a profile spells its key in one place, so the registration
/// and the resolve cannot part.
/// </summary>
/// <remarks>
/// The type lives in the test assembly because that is where the owner lives: nothing in the
/// library receives back-channel logout tokens yet, and this suite is the only thing composing the
/// profile. A key published from a package that neither registers nor resolves it would be a name
/// with no owner, and a public constant is frozen the moment it ships, since consumers spell it
/// literally. On the day a receiver exists, this file moves to its package unchanged.
/// </remarks>
public static class BackChannelLogoutValidation
{
    /// <summary>
    /// The profile's service key: the token's own <c>typ</c>, fixed by OpenID Connect
    /// Back-Channel Logout 1.0 Section 2.4. The key is the wire discriminator of the token kind
    /// because that is precisely what profiles part over, but the two readings stay spelled apart
    /// on purpose - <see cref="JsonWebTokenTypes.LogoutToken"/> stands wherever a wire value is
    /// meant, the header the profile pins and the header a fixture writes, and this name stands
    /// where the question is which profile.
    /// </summary>
    public const string ProfileKey = JsonWebTokenTypes.LogoutToken;
}
