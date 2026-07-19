// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
        var relaxed = new SecureHttpFetchOptions { AllowedSchemes = null, BlockPrivateNetworks = false };
        var result = await CreateValidator(relaxed)
            .ValidateAsync(CreateContext(new Uri("http://localhost:15555/backchannel-logout")));
        Assert.Null(result);
    }
}
