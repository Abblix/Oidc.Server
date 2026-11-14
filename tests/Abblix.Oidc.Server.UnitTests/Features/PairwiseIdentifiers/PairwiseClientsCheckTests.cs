// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// A tenant's client taking pairwise identifiers is refused at startup where the tenant has no key to seal them,
/// rather than served and failing each token request.
/// </summary>
public class PairwiseClientsCheckTests
{
    private static readonly PairwiseSubjectSettings Key = new() { Salt = Convert.ToBase64String(new byte[32]) };

    private static ClientInfo PairwiseClient(string id) => new(id) { SubjectType = SubjectTypes.Pairwise };

    private static TenantDefinition Tenant(string id, PairwiseSubjectSettings? key, params ClientInfo[] clients) => new()
    {
        Id = id,
        Issuer = new Uri($"https://auth.example.com/tenants/{id}"),
        Clients = clients,
        PairwiseSubject = key,
    };

    [Fact]
    public void APairwiseClient_WithoutAKey_IsRefused()
    {
        var tenant = Tenant("acme", null, new ClientInfo("public"), PairwiseClient("pairwise"));

        var refusal = Assert.Single(new PairwiseClientsCheck().Check([tenant], new OidcOptions()));

        Assert.Contains("The clients 'pairwise' take pairwise subject identifiers", refusal.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void APairwiseClient_WithAKey_PassesTheCheck()
    {
        var tenant = Tenant("acme", Key, PairwiseClient("pairwise"));

        Assert.Empty(new PairwiseClientsCheck().Check([tenant], new OidcOptions()));
    }

    /// <summary>
    /// Each tenant seals its pairwise identifiers with its own key, so the tenant without one is refused, named,
    /// while the tenant with one is not.
    /// </summary>
    [Fact]
    public void ATenantsPairwiseClient_WithoutTheTenantsKey_IsRefused_NamingTheTenant()
    {
        var refusal = Assert.Single(new PairwiseClientsCheck().Check(
            [
                Tenant("acme", null, PairwiseClient("pairwise")),
                Tenant("globex", Key, PairwiseClient("pairwise")),
            ],
            new OidcOptions()));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains("Tenant 'acme': The clients 'pairwise'", refusal.Message, StringComparison.Ordinal);
    }
}
