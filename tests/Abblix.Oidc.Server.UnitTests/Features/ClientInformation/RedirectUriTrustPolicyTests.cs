// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

public sealed class RedirectUriTrustPolicyTests
{
    private static readonly TenantDefinition Tenant = new TestIssuer().ToTenant();

    /// <summary>
    /// The policy answers from the client's record alone, decided when the client was created: it holds no settings
    /// and no store, so every replica gives the same answer for the same record.
    /// </summary>
    [Theory]
    [InlineData(ClientTrust.Trusted, true)]
    [InlineData(ClientTrust.Untrusted, false)]
    public async Task TheAnswer_IsTheClientsRecordedTrust(ClientTrust trust, bool trusted)
    {
        var client = new ClientInfo("client-1") { Trust = trust };

        Assert.Equal(trusted, await new RedirectUriTrustPolicy().IsTrustedAsync(Tenant, client));
    }

    /// <summary>
    /// A value the enumeration does not name is refused rather than read as either answer.
    /// </summary>
    [Fact]
    public async Task AnUnknownTrust_IsRefused()
    {
        var client = new ClientInfo("client-1") { Trust = (ClientTrust)99 };

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => new RedirectUriTrustPolicy().IsTrustedAsync(Tenant, client));
    }
}
