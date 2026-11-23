// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// How the server tells client ids apart: a request names a client only by its id exactly as the client holds it,
/// while ids differing only in the case of their letters are never held by two clients of one tenant.
/// </summary>
/// <remarks>
/// draft-ietf-oauth-client-id-metadata-document section 3 has Client Identifier URLs "compared using simple string
/// comparison, as defined in Section 6.2.1 of [RFC3986]", and every other client id is compared the same way, so one
/// spelling never reaches a client registered under another. Holding the ids apart regardless of case keeps a client
/// from being registered under a spelling of an id another client holds.
/// </remarks>
internal static class ClientIdComparison
{
    /// <summary>
    /// Compares ids for holding: two that differ only in case are one id here, so a store keyed by it holds at most one
    /// of them.
    /// </summary>
    public static readonly StringComparer Held = StringComparer.OrdinalIgnoreCase;

    /// <summary>
    /// Whether <paramref name="clientId"/> names <paramref name="client"/>, being exactly its id: a store holding ids by
    /// <see cref="Held"/>, the host's own included, may answer a lookup with a client held under another spelling.
    /// </summary>
    /// <param name="client">The client a store answered the lookup with.</param>
    /// <param name="clientId">The id the lookup asked for.</param>
    public static bool IsNamedBy(this ClientInfo client, string clientId)
        => string.Equals(client.ClientId, clientId, StringComparison.Ordinal);
}
