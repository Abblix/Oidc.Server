// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.MultiTenancy;

/// <summary>
/// The warning of a trusted issuer that is a tenant this server serves refuses nothing, so a catalog that cannot
/// answer yet, as one of the host's own over a store not reachable at startup, does not stop the server starting.
/// </summary>
public class TrustedTenantIssuersWarningTests
{
    [Fact]
    public async Task ACatalogThatCannotAnswer_DoesNotStopTheStart()
    {
        var catalog = new Mock<ITenantCatalog>();
        catalog
            .Setup(c => c.FindByAddressAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("The store of tenants cannot be reached."));
        var options = Options.Create(new OidcOptions
        {
            JwtBearer = new JwtBearerOptions
            {
                TrustedIssuers =
                    [new TrustedIssuer { Issuer = "https://idp.example.com", JwksUri = new Uri("https://idp.example.com/jwks") }],
            },
        });
        var warning = new TrustedTenantIssuersWarning(
            NullLogger<TrustedTenantIssuersWarning>.Instance, options, catalog.Object);

        await warning.StartAsync(TestContext.Current.CancellationToken);

        catalog.Verify(
            c => c.FindByAddressAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
