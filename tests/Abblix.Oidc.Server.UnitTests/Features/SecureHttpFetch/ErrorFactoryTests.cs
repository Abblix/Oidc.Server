// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Unit tests for <see cref="ErrorFactory"/> verifying correct OIDC error creation
/// for secure HTTP fetching operations.
/// </summary>
public class ErrorFactoryTests
{
    /// <summary>
    /// Verifies basic error creation with valid description.
    /// Per OIDC specification, error responses must include error code and description.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_WithValidDescription_ShouldCreateError()
    {
        // Arrange
        var description = "Unable to fetch content";

        // Act
        var error = ErrorFactory.InvalidClientMetadata(description);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Equal(description, error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error creation with empty description.
    /// Empty descriptions should be allowed for flexible error handling.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_WithEmptyDescription_ShouldCreateError()
    {
        // Arrange
        var description = string.Empty;

        // Act
        var error = ErrorFactory.InvalidClientMetadata(description);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Equal(string.Empty, error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error creation with long description.
    /// Long error descriptions should be preserved for detailed debugging.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_WithLongDescription_ShouldCreateError()
    {
        // Arrange
        var description = new string('a', 1000);

        // Act
        var error = ErrorFactory.InvalidClientMetadata(description);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Equal(1000, error.ErrorDescription.Length);
    }

    /// <summary>
    /// Verifies error creation with special characters in description.
    /// Special characters should be preserved in error descriptions.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_WithSpecialCharacters_ShouldCreateError()
    {
        // Arrange
        var description = "Error with \"quotes\", newlines\n and special chars: <>&";

        // Act
        var error = ErrorFactory.InvalidClientMetadata(description);

        // Assert
        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains("quotes", error.ErrorDescription);
        Assert.Contains("special chars", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies error code is always InvalidClientMetadata.
    /// The error code must be consistent as per OIDC Dynamic Client Registration spec.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_ShouldAlwaysUseCorrectErrorCode()
    {
        // Arrange & Act
        var error1 = ErrorFactory.InvalidClientMetadata("Test 1");
        var error2 = ErrorFactory.InvalidClientMetadata("Test 2");
        var error3 = ErrorFactory.InvalidClientMetadata("Test 3");

        // Assert
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error1.Error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error2.Error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error3.Error);
    }

    /// <summary>
    /// Verifies different descriptions create independent error instances.
    /// Each error should be distinct to avoid shared state issues.
    /// </summary>
    [Fact]
    public void InvalidClientMetadata_MultipleCalls_ShouldCreateIndependentInstances()
    {
        // Arrange & Act
        var error1 = ErrorFactory.InvalidClientMetadata("First error");
        var error2 = ErrorFactory.InvalidClientMetadata("Second error");

        // Assert
        Assert.NotSame(error1, error2);
        Assert.Equal("First error", error1.ErrorDescription);
        Assert.Equal("Second error", error2.ErrorDescription);
    }
}
