// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The change and removal of a registration the built-in client stores share: each takes effect only on the
/// registration still holding the token identifier it was decided on.
/// </summary>
internal static class RegisteredClients
{
    /// <summary>
    /// Replaces the registration under <paramref name="updated"/>'s client id with it, if the registration held there
    /// still carries <paramref name="current"/>'s token identifier.
    /// </summary>
    public static bool TryReplace(
        this ConcurrentDictionary<string, RegisteredClient> registrations,
        RegisteredClient current,
        RegisteredClient updated)
        => registrations.TryGetValue(updated.ClientInfo.ClientId, out var held) &&
           held.RegistrationAccessTokenId == current.RegistrationAccessTokenId &&
           registrations.TryUpdate(updated.ClientInfo.ClientId, updated, held);

    /// <summary>
    /// Removes the registration under <paramref name="current"/>'s client id, if it still carries
    /// <paramref name="current"/>'s token identifier.
    /// </summary>
    public static bool TryRemove(
        this ConcurrentDictionary<string, RegisteredClient> registrations,
        RegisteredClient current)
        => registrations.TryGetValue(current.ClientInfo.ClientId, out var held) &&
           held.RegistrationAccessTokenId == current.RegistrationAccessTokenId &&
           registrations.TryRemove(new KeyValuePair<string, RegisteredClient>(current.ClientInfo.ClientId, held));
}
