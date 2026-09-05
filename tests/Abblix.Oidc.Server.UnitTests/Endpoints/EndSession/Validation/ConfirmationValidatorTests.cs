// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="ConfirmationValidator"/> verifying confirmation validation
/// for end-session requests per OIDC Session Management specification.
/// </summary>
public class ConfirmationValidatorTests
{
    private readonly ConfirmationValidator _validator;

    public ConfirmationValidatorTests()
    {
        _validator = new ConfirmationValidator();
    }

    private static EndSessionValidationContext CreateContext(
        bool? confirmed = null,
        string? idTokenHint = null)
    {
        var request = new EndSessionRequest
        {
            Confirmed = confirmed,
            IdTokenHint = idTokenHint,
        };
        return new EndSessionValidationContext(request);
    }

    /// <summary>
    /// Verifies successful validation when request is confirmed.
    /// Per OIDC Session Management, confirmed requests don't require ID token hint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithConfirmedRequest_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(confirmed: true, idTokenHint: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies successful validation when ID token hint provided.
    /// Per OIDC Session Management, ID token hint can substitute for confirmation.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithIdTokenHint_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(confirmed: false, idTokenHint: "id_token_value");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies successful validation when both confirmed and ID token hint provided.
    /// Either condition alone is sufficient.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithBothConfirmedAndIdTokenHint_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(confirmed: true, idTokenHint: "id_token_value");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies error when neither confirmed nor ID token hint provided.
    /// Per OIDC Session Management, one of these is required.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithoutConfirmationOrIdTokenHint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(confirmed: false, idTokenHint: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
        Assert.Contains("requires to be confirmed", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error when confirmed is null and no ID token hint.
    /// Null confirmation is treated as false.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullConfirmation_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(confirmed: null, idTokenHint: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }

    /// <summary>
    /// Verifies successful validation with null confirmation but ID token hint present.
    /// ID token hint is sufficient even when confirmation is null.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNullConfirmationButIdTokenHint_ShouldSucceed()
    {
        // Arrange
        var context = CreateContext(confirmed: null, idTokenHint: "id_token_value");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies empty ID token hint is not sufficient for confirmation.
    /// Empty string is treated as no value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyIdTokenHint_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(confirmed: false, idTokenHint: "");

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }

    /// <summary>
    /// Verifies explicit false confirmation requires ID token hint.
    /// False and null are treated the same.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFalseConfirmation_ShouldRequireIdTokenHint()
    {
        // Arrange
        var context = CreateContext(confirmed: false, idTokenHint: null);

        // Act
        var error = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }
}
