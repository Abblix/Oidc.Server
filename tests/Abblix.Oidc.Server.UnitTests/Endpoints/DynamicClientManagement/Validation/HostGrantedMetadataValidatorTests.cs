// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A registering client may narrow the resources and token exchange audiences the host grants it, never widen them,
/// and a host granting none lets it name none.
/// </summary>
public class HostGrantedMetadataValidatorTests
{
    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    private static async Task<string?> ValidateAsync(
        NewClientOptions granted,
        Uri[]? allowedResources = null,
        string[]? tokenExchangeAudiences = null)
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options.Setup(monitor => monitor.CurrentValue).Returns(new OidcOptions { NewClientOptions = granted });
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            AllowedResources = allowedResources,
            TokenExchangeAudiences = tokenExchangeAudiences,
        });

        return (await new HostGrantedMetadataValidator(options.Object).ValidateAsync(SingleIssuer.Tenant, context))
            ?.Error;
    }

    [Fact]
    public async Task ARegistrationNamingNeither_IsServed()
        => Assert.Null(await ValidateAsync(new NewClientOptions()));

    [Fact]
    public async Task AResourceWithinTheHostsSet_IsServed()
        => Assert.Null(await ValidateAsync(new NewClientOptions { AllowedResources = [Orders, Billing] }, [Orders]));

    [Fact]
    public async Task AResourceOutsideTheHostsSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions { AllowedResources = [Orders] }, [Billing]));

    [Fact]
    public async Task AResourceAHostGrantingNoneDidNotGrant_IsRefused()
        => Assert.Equal(ErrorCodes.InvalidClientMetadata, await ValidateAsync(new NewClientOptions(), [Orders]));

    [Fact]
    public async Task AnAudienceOutsideTheHostsSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { TokenExchangeAudiences = ["orders-api"] },
                tokenExchangeAudiences: ["billing-api"]));

    /// <summary>
    /// A value naming nothing is one the host did not grant, wherever it stands in the list, so the values after it
    /// are not let through unread.
    /// </summary>
    [Fact]
    public async Task AListLeadingWithNoValue_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { TokenExchangeAudiences = ["orders-api"] },
                tokenExchangeAudiences: [null!, "billing-api"]));

    [Fact]
    public async Task AnAudienceAHostGrantingNoneDidNotGrant_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions(), tokenExchangeAudiences: ["orders-api"]));
}
