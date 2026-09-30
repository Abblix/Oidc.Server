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
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.PairwiseIdentifiers;

/// <summary>
/// A configured client taking pairwise identifiers is refused at startup where no key would seal them, rather than
/// served and failing each token request.
/// </summary>
public class PairwiseClientsOptionsValidatorTests
{
    private static readonly PairwiseSubjectSettings Key = new() { Salt = Convert.ToBase64String(new byte[32]) };

    private static ClientInfo PairwiseClient(string id) => new(id) { SubjectType = SubjectTypes.Pairwise };

    private static PairwiseClientsOptionsValidator CheckWith(ISubjectTypeConverter converter)
        => new(new ServiceCollection().AddSingleton(converter).BuildServiceProvider());

    [Fact]
    public void APairwiseClient_WithoutAKey_IsRefused()
    {
        var options = new OidcOptions { Clients = [new ClientInfo("public"), PairwiseClient("pairwise")] };

        var result = CheckWith(new SubjectTypeConverter()).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("The clients 'pairwise' take pairwise subject identifiers", result.FailureMessage,
            StringComparison.Ordinal);
    }

    [Fact]
    public void APairwiseClient_WithAKey_PassesTheCheck()
    {
        var options = new OidcOptions { Clients = [PairwiseClient("pairwise")] };

        Assert.True(CheckWith(new SubjectTypeConverter(Key)).Validate(null, options).Succeeded);
    }

    /// <summary>
    /// A host's own converter may issue pairwise identifiers without the server's key, and its answer is the one
    /// that counts.
    /// </summary>
    [Fact]
    public void APairwiseClient_OfAConverterIssuingThemItsOwnWay_PassesTheCheck()
    {
        var options = new OidcOptions { Clients = [PairwiseClient("pairwise")] };
        var converter = new Mock<ISubjectTypeConverter>();
        converter.Setup(c => c.SubjectTypesSupported).Returns([SubjectTypes.Public, SubjectTypes.Pairwise]);

        Assert.True(CheckWith(converter.Object).Validate(null, options).Succeeded);
    }

    [Fact]
    public void ATenantsPairwiseClient_WithoutTheTenantsKey_IsRefused_NamingTheTenant()
    {
        var options = new MultiTenancyOptions
        {
            Tenants =
            [
                new TenantDefinition
                {
                    Id = "acme",
                    Issuer = "https://auth.example.com/tenants/acme",
                    Clients = [PairwiseClient("pairwise")],
                },
                new TenantDefinition
                {
                    Id = "globex",
                    Issuer = "https://auth.example.com/tenants/globex",
                    Clients = [PairwiseClient("pairwise")],
                    PairwiseSubject = Key,
                },
            ],
        };

        var result = new MultiTenancyOptionsValidator().Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("Tenant 'acme': The clients 'pairwise'", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("Tenant 'globex'", result.FailureMessage, StringComparison.Ordinal);
    }
}
