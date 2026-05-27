// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.AuthorizationDetails;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Covers the authorize/PAR pipeline step that gates RFC 9396 authorization_details: per-client
/// allowlist enforcement, composite-validator delegation, and propagation of the validated array
/// onto the context for downstream emitters.
/// </summary>
public class AuthorizationDetailsRequestValidatorTests
{
    [Fact]
    public async Task ValidateAsync_NoAuthorizationDetails_Passes()
    {
        var validator = NewValidator();
        var context = NewContext(authorizationDetails: null);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_EmptyAllowlistOnClient_RejectsAnyRequest()
    {
        var validator = NewValidator();
        var context = NewContext(
            clientAllowlist: [],
            authorizationDetails: [new AuthorizationDetail { Type = "payment_initiation" }]);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_TypeNotInAllowlist_Rejects()
    {
        var validator = NewValidator();
        var context = NewContext(
            clientAllowlist: ["account_information"],
            authorizationDetails: [new AuthorizationDetail { Type = "payment_initiation" }]);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, result.Error);
        Assert.Contains("payment_initiation", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_TypeInAllowlist_DelegatesToComposite()
    {
        var compositeMock = new Mock<IAuthorizationDetailsValidator>();
        var validated = new[] { new AuthorizationDetail { Type = "payment_initiation" } };
        compositeMock
            .Setup(c => c.ValidateAsync(It.IsAny<System.Collections.Generic.IEnumerable<AuthorizationDetail>>(),
                It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<System.Collections.Generic.IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>
                .Success(validated));

        var validator = new AuthorizationDetailsRequestValidator(compositeMock.Object);
        var context = NewContext(
            clientAllowlist: ["payment_initiation"],
            authorizationDetails: validated);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
        Assert.NotNull(context.AuthorizationDetails);
        Assert.Single(context.AuthorizationDetails);
        Assert.Equal("payment_initiation", context.AuthorizationDetails[0].Type);
    }

    [Fact]
    public async Task ValidateAsync_CompositeRejects_RejectsWithInvalidAuthorizationDetails()
    {
        var compositeMock = new Mock<IAuthorizationDetailsValidator>();
        compositeMock
            .Setup(c => c.ValidateAsync(It.IsAny<System.Collections.Generic.IEnumerable<AuthorizationDetail>>(),
                It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<System.Collections.Generic.IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>
                .Failure(new AuthorizationDetailValidationError("unknown type: x")));

        var validator = new AuthorizationDetailsRequestValidator(compositeMock.Object);
        var context = NewContext(
            authorizationDetails: [new AuthorizationDetail { Type = "x" }]);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, result.Error);
        Assert.Contains("unknown type", result.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAsync_NullClientAllowlist_NoPerClientConstraint()
    {
        // null allowlist on ClientInfo means «no per-client constraint, fall back to server-wide»
        // — the composite is the sole gate. Verify the validator delegates without rejecting on
        // per-client check.
        var compositeMock = new Mock<IAuthorizationDetailsValidator>();
        var validated = new[] { new AuthorizationDetail { Type = "x" } };
        compositeMock
            .Setup(c => c.ValidateAsync(It.IsAny<System.Collections.Generic.IEnumerable<AuthorizationDetail>>(),
                It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result<System.Collections.Generic.IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>
                .Success(validated));

        var validator = new AuthorizationDetailsRequestValidator(compositeMock.Object);
        var context = NewContext(
            clientAllowlist: null,
            authorizationDetails: validated);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
    }

    private static AuthorizationDetailsRequestValidator NewValidator()
    {
        var compositeMock = new Mock<IAuthorizationDetailsValidator>();
        compositeMock
            .Setup(c => c.ValidateAsync(It.IsAny<System.Collections.Generic.IEnumerable<AuthorizationDetail>>(),
                It.IsAny<ClientInfo>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((System.Collections.Generic.IEnumerable<AuthorizationDetail> d, ClientInfo _, CancellationToken _) =>
                Result<System.Collections.Generic.IReadOnlyList<AuthorizationDetail>, AuthorizationDetailValidationError>
                    .Success(System.Linq.Enumerable.ToArray(d)));
        return new AuthorizationDetailsRequestValidator(compositeMock.Object);
    }

    private static AuthorizationValidationContext NewContext(
        string[]? clientAllowlist = null,
        AuthorizationDetail[]? authorizationDetails = null)
    {
        var clientInfo = new ClientInfo("test-client")
        {
            AuthorizationDetailsTypes = clientAllowlist,
        };
        return new AuthorizationValidationContext(new AuthorizationRequest
        {
            AuthorizationDetailsRaw = authorizationDetails.ToRawJsonArray(),
        })
        {
            ClientInfo = clientInfo,
        };
    }
}
