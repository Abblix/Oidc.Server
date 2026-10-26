// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// Unit tests for <see cref="InitialAccessTokenRevocationProvider"/> verifying revocation checks against the subjects
/// the tenant lists in <see cref="TenantDefinition.RevokedInitialAccessTokenSubjects"/>.
/// </summary>
public class InitialAccessTokenRevocationProviderTests
{
    private readonly InitialAccessTokenRevocationProvider _provider = new();

    private static TenantDefinition Revoking(params string[] subjects)
        => new()
        {
            Id = SingleIssuer.Tenant.Id,
            Issuer = SingleIssuer.Tenant.Issuer,
            RevokedInitialAccessTokenSubjects = subjects,
        };

    [Fact]
    public async Task IsRevokedAsync_WithEmptySet_ShouldReturnFalse()
    {
        var result = await _provider.IsRevokedAsync(SingleIssuer.Tenant, "any-subject");

        Assert.False(result);
    }

    [Fact]
    public async Task IsRevokedAsync_WithRevokedSubject_ShouldReturnTrue()
    {
        var result = await _provider.IsRevokedAsync(Revoking("revoked-1", "revoked-2"), "revoked-1");

        Assert.True(result);
    }

    [Fact]
    public async Task IsRevokedAsync_WithNonRevokedSubject_ShouldReturnFalse()
    {
        var result = await _provider.IsRevokedAsync(Revoking("revoked-1"), "not-revoked");

        Assert.False(result);
    }

    /// <summary>
    /// A subject revoked at one tenant leaves a token of the same subject another tenant issued alone.
    /// </summary>
    [Fact]
    public async Task ASubjectRevokedAtOneTenant_IsNotRevokedAtAnother()
    {
        var revoking = Revoking("partner-app");
        var other = new TenantDefinition { Id = "globex", Issuer = new System.Uri("https://globex.example.com") };

        Assert.True(await _provider.IsRevokedAsync(revoking, "partner-app"));
        Assert.False(await _provider.IsRevokedAsync(other, "partner-app"));
    }

    /// <summary>
    /// Subjects still listed in the server options, which the server no longer reads, stop it from starting, so the
    /// tokens they revoke are not accepted again.
    /// </summary>
    [Fact]
    public void SubjectsLeftInTheServerOptions_AreRefused()
    {
        var validator = new RevokedInitialAccessTokenSubjectsValidator();
#pragma warning disable CS0618
        var leftOver = new OidcOptions { RevokedInitialAccessTokenSubjects = ["partner-app"] };
#pragma warning restore CS0618

        Assert.True(validator.Validate(null, leftOver).Failed);
        Assert.True(validator.Validate(null, new OidcOptions()).Succeeded);
    }
}
