// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
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
/// itself a client; a list of prefixes is the host's own assessment of the URLs it serves. And, while
/// <see cref="OidcOptions.RequireInitialAccessToken"/> is <c>false</c> and anybody may register a client, every client
/// but one the tenant settings declare or the host's own store still supplies: a registered one, whenever it
/// registered, and one whose registration is gone, which nobody answers for any more. The store is asked again rather
/// than taken from the lookup the request made, so a registration removed meanwhile is not trusted for being absent.
/// </remarks>
/// <param name="options">The server's options, read at each decision.</param>
/// <param name="registrations">The store of dynamically registered clients.</param>
/// <param name="clients">The client store the server resolves clients by, the host's own where it registers one.</param>
public sealed class RedirectUriTrustPolicy(
    IOptionsMonitor<OidcOptions> options,
    IClientInfoManager registrations,
    IClientInfoProvider clients)
    : IRedirectUriTrustPolicy
{
    /// <inheritdoc />
    public async Task<bool> IsTrustedAsync(TenantDefinition tenant, ClientInfo client)
    {
        var settings = options.CurrentValue;

        if (client.ResolvedFromMetadataDocument)
            return !OpenRegistration.AdmitsAnyDocument(settings);

        if (!OpenRegistration.AdmitsAnyRegistrant(settings) ||
            tenant.Clients.Any(declared => declared.IsNamedBy(client.ClientId)))
        {
            return true;
        }

        if (await registrations.TryFindRegisteredClientAsync(tenant, client.ClientId) is not null)
            return false;

        return (await clients.FindClientAsync(tenant, client.ClientId)).TryGetSuccess(out _);
    }
}
