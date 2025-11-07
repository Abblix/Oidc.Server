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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Unit tests for <see cref="BackChannelAuthenticationValidatorComposite"/> verifying
/// composite validator pattern per OpenID Connect CIBA specification.
/// </summary>
public class BackChannelAuthenticationValidatorCompositeTests
{
    private BackChannelAuthenticationValidationContext CreateContext()
    {
        var request = new BackChannelAuthenticationRequest
        {
            Scope = new[] { "openid" },
            LoginHint = "user@example.com"
        };

        var clientRequest = new ClientRequest { ClientId = "test-client" };

        return new BackChannelAuthenticationValidationContext(request, clientRequest)
        {
            ClientInfo = new ClientInfo("test-client")
        };
    }

    /// <summary>
    /// Verifies validation succeeds when all validators pass.
    /// Per composite pattern, all validators must succeed for overall success.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAllValidatorsPassing_ShouldReturnNull()
    {
        // Arrange
        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        validator1.Verify(v => v.ValidateAsync(context), Times.Once);
        validator2.Verify(v => v.ValidateAsync(context), Times.Once);
        validator3.Verify(v => v.ValidateAsync(context), Times.Once);
    }

    /// <summary>
    /// Verifies validation stops at first error.
    /// Per fail-fast pattern, validation should not continue after first failure.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithFirstValidatorFailing_ShouldReturnErrorWithoutCallingOthers()
    {
        // Arrange
        var error = new OidcError(ErrorCodes.InvalidRequest, "First validator failed");

        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync(error);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(error, result);
        validator1.Verify(v => v.ValidateAsync(context), Times.Once);
        validator2.Verify(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()), Times.Never);
        validator3.Verify(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()), Times.Never);
    }

    /// <summary>
    /// Verifies validation stops at second validator error.
    /// First validator succeeds, second fails, third not called.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSecondValidatorFailing_ShouldStopAtSecond()
    {
        // Arrange
        var error = new OidcError(ErrorCodes.InvalidScope, "Second validator failed");

        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync(error);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(error, result);
        validator1.Verify(v => v.ValidateAsync(context), Times.Once);
        validator2.Verify(v => v.ValidateAsync(context), Times.Once);
        validator3.Verify(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()), Times.Never);
    }

    /// <summary>
    /// Verifies validation stops at last validator error.
    /// All validators except last succeed, last fails.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithLastValidatorFailing_ShouldReturnError()
    {
        // Arrange
        var error = new OidcError(ErrorCodes.InvalidTarget, "Last validator failed");

        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync(error);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(error, result);
        validator1.Verify(v => v.ValidateAsync(context), Times.Once);
        validator2.Verify(v => v.ValidateAsync(context), Times.Once);
        validator3.Verify(v => v.ValidateAsync(context), Times.Once);
    }

    /// <summary>
    /// Verifies validation succeeds with empty validator array.
    /// No validators means no validation errors.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoValidators_ShouldReturnNull()
    {
        // Arrange
        var composite = new BackChannelAuthenticationValidatorComposite(Array.Empty<IBackChannelAuthenticationContextValidator>());
        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies validation succeeds with single validator that passes.
    /// Single validator composite should work correctly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSingleValidatorPassing_ShouldReturnNull()
    {
        // Arrange
        var validator = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        validator.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        var composite = new BackChannelAuthenticationValidatorComposite(new[] { validator.Object });
        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        validator.Verify(v => v.ValidateAsync(context), Times.Once);
    }

    /// <summary>
    /// Verifies validation fails with single validator that fails.
    /// Single validator error should be returned immediately.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSingleValidatorFailing_ShouldReturnError()
    {
        // Arrange
        var error = new OidcError(ErrorCodes.UnauthorizedClient, "Validator failed");

        var validator = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        validator.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .ReturnsAsync(error);

        var composite = new BackChannelAuthenticationValidatorComposite(new[] { validator.Object });
        var context = CreateContext();

        // Act
        var result = await composite.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Same(error, result);
        validator.Verify(v => v.ValidateAsync(context), Times.Once);
    }

    /// <summary>
    /// Verifies same context instance is passed to all validators.
    /// Context modifications by earlier validators are visible to later ones.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassSameContextToAllValidators()
    {
        // Arrange
        BackChannelAuthenticationValidationContext? context1 = null;
        BackChannelAuthenticationValidationContext? context2 = null;
        BackChannelAuthenticationValidationContext? context3 = null;

        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx => context1 = ctx))
            .ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx => context2 = ctx))
            .ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(ctx => context3 = ctx))
            .ReturnsAsync((OidcError?)null);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        await composite.ValidateAsync(context);

        // Assert
        Assert.NotNull(context1);
        Assert.NotNull(context2);
        Assert.NotNull(context3);
        Assert.Same(context, context1);
        Assert.Same(context, context2);
        Assert.Same(context, context3);
    }

    /// <summary>
    /// Verifies validators are executed in order.
    /// Composite must respect validator array order.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldExecuteValidatorsInOrder()
    {
        // Arrange
        var executionOrder = new System.Collections.Generic.List<int>();

        var validator1 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IBackChannelAuthenticationContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(_ => executionOrder.Add(1)))
            .ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(_ => executionOrder.Add(2)))
            .ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<BackChannelAuthenticationValidationContext>()))
            .Callback(new Action<BackChannelAuthenticationValidationContext>(_ => executionOrder.Add(3)))
            .ReturnsAsync((OidcError?)null);

        var composite = new BackChannelAuthenticationValidatorComposite(new[]
        {
            validator1.Object,
            validator2.Object,
            validator3.Object
        });

        var context = CreateContext();

        // Act
        await composite.ValidateAsync(context);

        // Assert
        Assert.Equal(new[] { 1, 2, 3 }, executionOrder);
    }
}
