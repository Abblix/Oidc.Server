// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// The tenant the test host serves, for a test that calls the server's services itself rather than through a
/// request, as a host does from its own code: outside a request nothing resolves the tenant, so the call runs
/// within it.
/// </summary>
public static class TestTenant
{
    /// <summary>
    /// Runs what follows within the test host's tenant, until the scope is disposed.
    /// </summary>
    /// <remarks>
    /// Synchronous on purpose: a scope entered inside an async method ends for its caller when the method returns.
    /// </remarks>
    public static TenantScope Enter(IServiceProvider services) => TenantScope.Enter(Of(services));

    /// <summary>
    /// The test host's tenant, as its settings declare it.
    /// </summary>
    public static TenantDefinition Of(IServiceProvider services)
        => services.GetRequiredService<IOptions<OidcOptions>>().Value.Tenants.Single(
            tenant => tenant.Id == TestTenantSettings.TenantId);

    /// <summary>
    /// Serves the suite's tenant from a host a test builds itself, signing with <paramref name="signingKeys"/>.
    /// </summary>
    /// <remarks>
    /// The issuer and id of the shared test host's tenant: the license counts tenants across the process.
    /// </remarks>
    public static void ServeOn(OidcOptions options, params JsonWebKey[] signingKeys)
        => options.Tenants.Add(new TenantDefinition
        {
            Id = TestTenantSettings.TenantId,
            Issuer = TestConstants.IssuerUri,
            SigningKeys = signingKeys,
        });

    /// <summary>
    /// The server's revoker, each call made within the test host's tenant.
    /// </summary>
    public static ITokenRevoker RevokerOf(IServiceProvider services)
        => new TenantRevoker(services.GetRequiredService<ITokenRevoker>(), services);

    private sealed class TenantRevoker(ITokenRevoker inner, IServiceProvider services) : ITokenRevoker
    {
        public async Task RevokeSubjectAsync(
            string subject, DateTimeOffset? before = null, CancellationToken cancellationToken = default)
        {
            using var tenant = Enter(services);
            await inner.RevokeSubjectAsync(subject, before, cancellationToken);
        }

        public async Task RevokeSessionAsync(
            string sessionId, DateTimeOffset? before = null, CancellationToken cancellationToken = default)
        {
            using var tenant = Enter(services);
            await inner.RevokeSessionAsync(sessionId, before, cancellationToken);
        }

        public async Task RevokeSubjectAtClientAsync(
            string subject, string clientId, DateTimeOffset? before = null, CancellationToken cancellationToken = default)
        {
            using var tenant = Enter(services);
            await inner.RevokeSubjectAtClientAsync(subject, clientId, before, cancellationToken);
        }
    }
}
