// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Trusts the redirect URIs of every client somebody answering for the deployment let in, and of no other: RFC 9700
/// section 4.11.2 names "the source of the redirection URI and other client data" among what the decision takes into
/// account.
/// </summary>
/// <remarks>
/// Two kinds of client are untrusted. One resolved from its client ID metadata document while
/// <see cref="ClientIdMetadataDocumentOptions.AllowedClientIdPrefixes"/> names no prefix, since any URL may then name
/// itself a client; a list of prefixes is the host's own assessment of the URLs it serves. And one registered
/// dynamically while <see cref="OidcOptions.RequireInitialAccessToken"/> is <c>false</c>, since anybody may then
/// register one: the setting is read as it stands, so opening registration makes every registered client untrusted,
/// whenever it registered. A client declared in the tenant settings or supplied by the host's own store is trusted.
/// </remarks>
/// <param name="options">The server's options, read at each decision.</param>
/// <param name="registrations">The store of dynamically registered clients.</param>
public sealed class RedirectUriTrustPolicy(IOptionsMonitor<OidcOptions> options, IClientInfoManager registrations)
    : IRedirectUriTrustPolicy
{
    /// <inheritdoc />
    public async Task<bool> IsTrustedAsync(TenantDefinition tenant, ClientInfo client)
    {
        var settings = options.CurrentValue;

        if (client.ResolvedFromMetadataDocument)
            return settings.ClientIdMetadataDocuments.AllowedClientIdPrefixes is { Length: > 0 };

        if (settings.RequireInitialAccessToken)
            return true;

        return await registrations.TryFindRegisteredClientAsync(tenant, client.ClientId) is null;
    }
}
