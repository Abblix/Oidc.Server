// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The one answer to whether a client acts as the resource server at a location, for every feature that asks it.
/// </summary>
internal static class ResourceServerClients
{
    /// <summary>
    /// Whether <paramref name="location"/>, as a token or an <c>authorization_details</c> entry names it, is one of the
    /// <see cref="ClientInfo.ResourceLocations"/> of <paramref name="client"/>, compared exactly as written
    /// (RFC 9396 section 12).
    /// </summary>
    public static bool IsResourceServerFor(this ClientInfo client, string location)
        => client.ResourceLocations is { } locations &&
           Array.Exists(locations, own => string.Equals(own.OriginalString, location, StringComparison.Ordinal));
}
