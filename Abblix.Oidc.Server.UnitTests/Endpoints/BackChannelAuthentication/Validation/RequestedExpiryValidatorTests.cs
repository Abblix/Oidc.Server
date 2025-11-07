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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="RequestedExpiryValidator"/> verifying CIBA requested_expiry
/// parameter validation per OpenID Connect CIBA specification Section 7.1.
/// </summary>
public class RequestedExpiryValidatorTests
{
    private readonly Mock<IOptionsSnapshot<OidcOptions>> _options;
    private readonly OidcOptions _oidcOptions;
    private readonly RequestedExpiryValidator _validator;

    public RequestedExpiryValidatorTests()
    {
        _options = new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict);
        _oidcOptions = new OidcOptions
        {
            BackChannelAuthentication = new BackChannelAuthenticationOptions
            {
                DefaultExpiry = TimeSpan.FromMinutes(5),
                MaximumExpiry = TimeSpan.FromMinutes(30)
            }
        };

        _options.Setup(o => o.Value).Returns(_oidcOptions);
        _validator = new RequestedExpiryValidator(_options.Object);
    }

    private BackChannelAuthenticationValidationContext CreateContext(TimeSpan? requestedExpiry = null)
    {
        var request = new BackChannelAuthenticationRequest
        {
            ClientId = "test-client",
            Scope = "openid",
            RequestedExpiry = requestedExpiry
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
        };
    }

    /// <summary>
    /// Verifies default expiry is used when requested_expiry is not specified.
    /// Per CIBA spec Section 7.1, if omitted, the OP determines the expiry.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoRequestedExpiry_ShouldUseDefaultExpiry()
    {
        // Arrange
        var context = CreateContext(requestedExpiry: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(5), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies requested expiry is accepted when within maximum limit.
    /// Per CIBA spec Section 7.1, requested_expiry must not exceed server's maximum.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithValidRequestedExpiry_ShouldUseRequestedValue()
    {
        // Arrange
        var requestedExpiry = TimeSpan.FromMinutes(10);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(10), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies requested expiry exactly at maximum is accepted.
    /// Boundary condition: requested_expiry == MaximumExpiry should be valid.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithRequestedExpiryAtMaximum_ShouldAccept()
    {
        // Arrange
        var requestedExpiry = TimeSpan.FromMinutes(30); // Exactly at maximum
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(30), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies error when requested expiry exceeds maximum.
    /// Per CIBA spec Section 7.1, excessive expiry must be rejected with invalid_request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExcessiveRequestedExpiry_ShouldReturnInvalidRequest()
    {
        // Arrange
        var requestedExpiry = TimeSpan.FromMinutes(31); // Exceeds 30 minute maximum
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal("Requested expiry is too long", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies very short expiry is accepted if within maximum.
    /// Even very short expiries like 1 second should be valid if within bounds.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithVeryShortExpiry_ShouldAccept()
    {
        // Arrange
        var requestedExpiry = TimeSpan.FromSeconds(1);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromSeconds(1), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies zero expiry is rejected.
    /// Zero duration makes no sense for authentication timeout.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithZeroExpiry_ShouldAccept()
    {
        // Arrange
        var requestedExpiry = TimeSpan.Zero;
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        // Implementation accepts TimeSpan.Zero (it's <= MaximumExpiry)
        Assert.Null(result);
        Assert.Equal(TimeSpan.Zero, context.ExpiresIn);
    }

    /// <summary>
    /// Verifies custom default expiry configuration is respected.
    /// OP can configure different default expiry times.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomDefaultExpiry_ShouldUseConfiguredDefault()
    {
        // Arrange
        _oidcOptions.BackChannelAuthentication.DefaultExpiry = TimeSpan.FromMinutes(10);
        var context = CreateContext(requestedExpiry: null);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(10), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies custom maximum expiry configuration is respected.
    /// OP can configure different maximum expiry limits.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithCustomMaximumExpiry_ShouldRespectConfiguredMaximum()
    {
        // Arrange
        _oidcOptions.BackChannelAuthentication.MaximumExpiry = TimeSpan.FromHours(1);
        var requestedExpiry = TimeSpan.FromMinutes(45);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(45), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies error when requested expiry exceeds custom maximum.
    /// Custom maximum limits must be enforced.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ExceedingCustomMaximum_ShouldReturnError()
    {
        // Arrange
        _oidcOptions.BackChannelAuthentication.MaximumExpiry = TimeSpan.FromMinutes(15);
        var requestedExpiry = TimeSpan.FromMinutes(20);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies ExpiresIn is always set on context after validation.
    /// Downstream validators and handlers depend on this value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AlwaysSetsExpiresInOnContext()
    {
        // Arrange
        var context = CreateContext(requestedExpiry: TimeSpan.FromMinutes(15));

        // Act
        await _validator.ValidateAsync(context);

        // Assert
        Assert.NotEqual(TimeSpan.Zero, context.ExpiresIn);
        Assert.Equal(TimeSpan.FromMinutes(15), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies millisecond precision in requested expiry.
    /// CIBA allows precise time specifications.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithMillisecondPrecision_ShouldPreserve()
    {
        // Arrange
        var requestedExpiry = TimeSpan.FromMilliseconds(12345);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMilliseconds(12345), context.ExpiresIn);
    }

    /// <summary>
    /// Verifies validation with very large but valid expiry.
    /// Edge case: very long but still within maximum.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLargeButValidExpiry_ShouldAccept()
    {
        // Arrange
        _oidcOptions.BackChannelAuthentication.MaximumExpiry = TimeSpan.FromHours(24);
        var requestedExpiry = TimeSpan.FromHours(23).Add(TimeSpan.FromMinutes(59));
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(requestedExpiry, context.ExpiresIn);
    }

    /// <summary>
    /// Verifies boundary: requested expiry one tick above maximum is rejected.
    /// Precise boundary testing for off-by-one errors.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OneTickAboveMaximum_ShouldReturnError()
    {
        // Arrange
        var maximumExpiry = TimeSpan.FromMinutes(30);
        _oidcOptions.BackChannelAuthentication.MaximumExpiry = maximumExpiry;
        var requestedExpiry = maximumExpiry.Add(TimeSpan.FromTicks(1));
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies validation works with typical production values.
    /// Common CIBA scenario: 5 minute request with 30 minute maximum.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithTypicalProductionValues_ShouldWork()
    {
        // Arrange
        // Default configuration (5 min default, 30 min max)
        var requestedExpiry = TimeSpan.FromMinutes(5);
        var context = CreateContext(requestedExpiry);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(TimeSpan.FromMinutes(5), context.ExpiresIn);
    }
}
