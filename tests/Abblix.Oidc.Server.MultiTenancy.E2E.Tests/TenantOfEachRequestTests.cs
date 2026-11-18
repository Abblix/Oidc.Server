// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Two tenants each registering a client under the same id with a redirect address of its own: each request is
/// served by the client of the tenant it is made at, so a service that kept the tenant of an earlier request would
/// find the other tenant's client and refuse the address this one registered.
/// </summary>
public sealed class TenantOfEachRequestTests : IAsyncLifetime
{
    private SignedInTenantsHost? _host;

    public async ValueTask InitializeAsync()
        => _host = await SignedInTenantsHost.StartAsync(tenantId => new ClientInfo(SignedInTenantsHost.ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
            AllowedGrantTypes = [GrantTypes.AuthorizationCode],
            RedirectUris = [RedirectOf(tenantId)],
            PkceRequired = true,
        });

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
            await _host.DisposeAsync();
    }

    private static Uri RedirectOf(string tenantId) => new($"https://{tenantId}.client.example.com/callback");

    /// <summary>
    /// An authorization at one tenant and then at the other is each answered with a code at the address the client
    /// of that tenant registered.
    /// </summary>
    [Fact]
    public async Task AuthorizationsAtEachTenantInTurn_AreEachServedByThatTenantsClient()
    {
        foreach (var (tenant, id) in new[] { (SignedInTenantsHost.Acme, "acme"), (SignedInTenantsHost.Globex, "globex") })
        {
            using var authorized = await _host!.AuthorizeAtAsync(tenant, RedirectOf(id).OriginalString);

            Assert.Equal(HttpStatusCode.SeeOther, authorized.StatusCode);
            Assert.Equal(RedirectOf(id).GetLeftPart(UriPartial.Path), authorized.Headers.Location!.GetLeftPart(UriPartial.Path));
        }
    }
}
