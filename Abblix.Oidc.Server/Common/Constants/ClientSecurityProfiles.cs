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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// The wire tokens for <see cref="ClientSecurityProfile"/> as carried in dynamic client registration
/// metadata, and the mapping between those tokens and the strongly-typed enum. The core configuration
/// uses the enum (like <see cref="ClientType"/>); the registration wire uses these strings (like
/// <c>subject_type</c> / <c>application_type</c>), and this class bridges the two.
/// </summary>
public static class ClientSecurityProfiles
{
    /// <summary>The wire token for <see cref="ClientSecurityProfile.None"/>.</summary>
    public const string None = "none";

    /// <summary>The wire token for <see cref="ClientSecurityProfile.Fapi2"/>.</summary>
    public const string Fapi2 = "fapi2";

    /// <summary>
    /// Maps a registration wire token to the enum. An absent or unrecognised value maps to
    /// <see cref="ClientSecurityProfile.None"/>; the registration validator rejects an explicitly
    /// invalid token up front (via <c>[AllowedValues]</c>), so this only ever sees a known token or
    /// nothing.
    /// </summary>
    public static ClientSecurityProfile Parse(string? value) => value switch
    {
        Fapi2 => ClientSecurityProfile.Fapi2,
        _ => ClientSecurityProfile.None,
    };

    /// <summary>
    /// Maps the enum to its registration wire token. <see cref="ClientSecurityProfile.None"/> maps to
    /// <c>null</c> so the registration response omits the field rather than echoing an explicit
    /// "no profile" — keeping the echoed metadata to what was actually registered.
    /// </summary>
    public static string? ToWire(ClientSecurityProfile profile) => profile switch
    {
        ClientSecurityProfile.Fapi2 => Fapi2,
        _ => null,
    };
}
