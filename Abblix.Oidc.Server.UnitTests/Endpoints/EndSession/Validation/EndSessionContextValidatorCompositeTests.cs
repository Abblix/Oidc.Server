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
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="EndSessionContextValidatorComposite"/> verifying composite
/// validator pattern for end-session validation.
/// </summary>
public class EndSessionContextValidatorCompositeTests
{
    private static EndSessionValidationContext CreateContext()
    {
        var request = new EndSessionRequest();
        return new EndSessionValidationContext(request);
    }

    /// <summary>
    /// Verifies successful validation when no validators provided.
    /// Empty validator list should succeed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNoValidators_ShouldSucceed()
    {
        // Arrange
        var validator = new EndSessionContextValidatorComposite([]);
        var context = CreateContext();

        // Act
        var error = await validator.ValidateAsync(context);

        // Assert
        Assert.Null(error);
    }

    /// <summary>
    /// Verifies successful validation when all validators succeed.
    /// All validators should be called in sequence.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAllValidatorsSucceeding_ShouldSucceed()
    {
        // Arrange
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object,
            validator3.Object
        ]);
        var context = CreateContext();

        // Act
        var error = await composite.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        validator1.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator2.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator3.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies error when first validator fails.
    /// First error should be returned immediately.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenFirstValidatorFails_ShouldReturnError()
    {
        // Arrange
        var error1 = new OidcError(ErrorCodes.InvalidRequest, "First validator error");
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync(error1);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object
        ]);
        var context = CreateContext();

        // Act
        var error = await composite.ValidateAsync(context);

        // Assert
        Assert.Same(error1, error);
        validator1.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator2.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies error when middle validator fails.
    /// Previous validators should be called, subsequent ones should not.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenMiddleValidatorFails_ShouldReturnError()
    {
        // Arrange
        var error2 = new OidcError(ErrorCodes.InvalidClient, "Second validator error");
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync(error2);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object,
            validator3.Object
        ]);
        var context = CreateContext();

        // Act
        var error = await composite.ValidateAsync(context);

        // Assert
        Assert.Same(error2, error);
        validator1.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator2.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator3.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies error when last validator fails.
    /// All previous validators should be called.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenLastValidatorFails_ShouldReturnError()
    {
        // Arrange
        var error3 = new OidcError(ErrorCodes.UnauthorizedClient, "Third validator error");
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);
        validator2.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);
        validator3.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync(error3);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object,
            validator3.Object
        ]);
        var context = CreateContext();

        // Act
        var error = await composite.ValidateAsync(context);

        // Assert
        Assert.Same(error3, error);
        validator1.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator2.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
        validator3.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }

    /// <summary>
    /// Verifies validators are called in order.
    /// Execution order should match array order.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldCallValidatorsInOrder()
    {
        // Arrange
        var callOrder = new System.Collections.Generic.List<int>();
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator3 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(_ => callOrder.Add(1)))
            .ReturnsAsync((OidcError?)null);
        validator2
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(_ => callOrder.Add(2)))
            .ReturnsAsync((OidcError?)null);
        validator3
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(_ => callOrder.Add(3)))
            .ReturnsAsync((OidcError?)null);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object,
            validator3.Object
        ]);
        var context = CreateContext();

        // Act
        await composite.ValidateAsync(context);

        // Assert
        Assert.Equal(new[] { 1, 2, 3 }, callOrder);
    }

    /// <summary>
    /// Verifies same context is passed to all validators.
    /// Context should be shared across validation chain.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPassSameContextToAllValidators()
    {
        // Arrange
        var capturedContexts = new System.Collections.Generic.List<EndSessionValidationContext>();
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => capturedContexts.Add(ctx)))
            .ReturnsAsync((OidcError?)null);
        validator2
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => capturedContexts.Add(ctx)))
            .ReturnsAsync((OidcError?)null);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object
        ]);
        var context = CreateContext();

        // Act
        await composite.ValidateAsync(context);

        // Assert
        Assert.Equal(2, capturedContexts.Count);
        Assert.Same(context, capturedContexts[0]);
        Assert.Same(context, capturedContexts[1]);
    }

    /// <summary>
    /// Verifies context modifications are preserved across validators.
    /// Validators can modify context for downstream validators.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ShouldPreserveContextModifications()
    {
        // Arrange
        var validator1 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        var validator2 = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);

        validator1
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .Callback(new Action<EndSessionValidationContext>(ctx => ctx.ClientId = "modified_client"))
            .ReturnsAsync((OidcError?)null);
        validator2
            .Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()))
            .ReturnsAsync((OidcError?)null);

        var composite = new EndSessionContextValidatorComposite([
            validator1.Object,
            validator2.Object
        ]);
        var context = CreateContext();

        // Act
        await composite.ValidateAsync(context);

        // Assert
        Assert.Equal("modified_client", context.ClientId);
        validator2.Verify(v => v.ValidateAsync(It.Is<EndSessionValidationContext>(c => c.ClientId == "modified_client")), Times.Once);
    }

    /// <summary>
    /// Verifies single validator in composite.
    /// Composite should work with one validator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithSingleValidator_ShouldWork()
    {
        // Arrange
        var validator = new Mock<IEndSessionContextValidator>(MockBehavior.Strict);
        validator.Setup(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>())).ReturnsAsync((OidcError?)null);

        var composite = new EndSessionContextValidatorComposite([validator.Object]);
        var context = CreateContext();

        // Act
        var error = await composite.ValidateAsync(context);

        // Assert
        Assert.Null(error);
        validator.Verify(v => v.ValidateAsync(It.IsAny<EndSessionValidationContext>()), Times.Once);
    }
}
