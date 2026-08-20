// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="BackChannelLogoutUriValidator"/> verifying that a client-supplied
/// backchannel_logout_uri is validated against the active SSRF policy at registration time.
/// </summary>
public class BackChannelLogoutUriValidatorTests
{
    private static BackChannelLogoutUriValidator CreateValidator(SecureHttpFetchOptions options)
        => new(new SecureUriValidator(Options.Create(options)));

    private static ClientRegistrationValidationContext CreateContext(Uri? backChannelLogoutUri)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            BackChannelLogoutUri = backChannelLogoutUri,
        });

    // Secure defaults: https-only, private networks blocked.
    private static SecureHttpFetchOptions SecureDefaults => new();

    [Fact]
    public async Task ValidateAsync_WithNoUri_ReturnsNull()
    {
        var result = await CreateValidator(SecureDefaults).ValidateAsync(CreateContext(null));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithPublicHttpsUri_ReturnsNull()
    {
        var result = await CreateValidator(SecureDefaults)
            .ValidateAsync(CreateContext(new Uri("https://client.example.com/backchannel-logout")));
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_WithRelativeUri_ReturnsInvalidClientMetadata()
    {
        var result = await CreateValidator(SecureDefaults)
            .ValidateAsync(CreateContext(new Uri("/backchannel-logout", UriKind.Relative)));
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WithHttpUri_UnderSecureDefaults_ReturnsInvalidClientMetadata()
    {
        var result = await CreateValidator(SecureDefaults)
            .ValidateAsync(CreateContext(new Uri("http://client.example.com/backchannel-logout")));
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WithLoopbackHost_UnderSecureDefaults_ReturnsInvalidClientMetadata()
    {
        var result = await CreateValidator(SecureDefaults)
            .ValidateAsync(CreateContext(new Uri("https://localhost/backchannel-logout")));
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_WithHttpLocalhost_WhenPolicyRelaxed_ReturnsNull()
    {
        var relaxed = new SecureHttpFetchOptions { AllowedSchemes = [], BlockPrivateNetworks = false };
        var result = await CreateValidator(relaxed)
            .ValidateAsync(CreateContext(new Uri("http://localhost:15555/backchannel-logout")));
        Assert.Null(result);
    }
}
