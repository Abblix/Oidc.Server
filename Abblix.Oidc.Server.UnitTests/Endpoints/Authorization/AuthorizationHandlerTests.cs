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
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.RequestFetching;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// Unit tests for <see cref="AuthorizationHandler"/> verifying request orchestration
/// (fetch → validate → process) per OAuth 2.0/OIDC specifications.
/// </summary>
public class AuthorizationHandlerTests
{
    private readonly Mock<IAuthorizationRequestFetcher> _fetcher;
    private readonly Mock<IAuthorizationRequestValidator> _validator;
    private readonly Mock<IAuthorizationRequestProcessor> _processor;
    private readonly AuthorizationHandler _handler;

    public AuthorizationHandlerTests()
    {
        _fetcher = new Mock<IAuthorizationRequestFetcher>(MockBehavior.Strict);
        _validator = new Mock<IAuthorizationRequestValidator>(MockBehavior.Strict);
        _processor = new Mock<IAuthorizationRequestProcessor>(MockBehavior.Strict);
        _handler = new AuthorizationHandler(_fetcher.Object, _validator.Object, _processor.Object);
    }

    private static AuthorizationRequest CreateRequest() => new()
    {
        ClientId = "client_123",
        ResponseType = [ResponseTypes.Code],
        RedirectUri = new Uri("https://client.example.com/callback"),
        Scope = [Scopes.OpenId],
    };

    /// <summary>
    /// Verifies successful authorization flow: fetch → validate → process.
    /// Tests happy path where all steps succeed.
    /// </summary>
    [Fact]
    public async Task HandleAsync_SuccessfulFlow_ShouldCallAllComponents()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            ClientInfo = new ClientInfo("client_123"),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(request, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, request.RedirectUri);

        _fetcher
            .Setup(f => f.FetchAsync(request))
            .ReturnsAsync(Result<AuthorizationRequest, AuthorizationRequestValidationError>
                .Success(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(fetchedRequest))
            .ReturnsAsync(Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>
                .Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(processedResponse);

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        Assert.NotNull(result);
        _fetcher.Verify(f => f.FetchAsync(request), Times.Once);
        _validator.Verify(v => v.ValidateAsync(fetchedRequest), Times.Once);
        _processor.Verify(p => p.ProcessAsync(validRequest), Times.Once);
    }

    /// <summary>
    /// Verifies fetch error handling.
    /// Per OAuth 2.0, fetch errors (PAR, request object) should return error response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_FetchError_ShouldReturnAuthorizationError()
    {
        // Arrange
        var request = CreateRequest();
        var fetchError = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidRequest,
            "Failed to fetch request object",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(request))
            .ReturnsAsync(Result<AuthorizationRequest, AuthorizationRequestValidationError>
                .Failure(fetchError));

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("Failed to fetch request object", error.ErrorDescription);
        _fetcher.Verify(f => f.FetchAsync(request), Times.Once);
        _validator.VerifyNoOtherCalls();
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies validation error handling.
    /// Per OAuth 2.0, validation errors should return error response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ValidationError_ShouldReturnAuthorizationError()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationError = new AuthorizationRequestValidationError(
            ErrorCodes.InvalidScope,
            "Invalid scope requested",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(request))
            .ReturnsAsync(Result<AuthorizationRequest, AuthorizationRequestValidationError>
                .Success(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(fetchedRequest))
            .ReturnsAsync(Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>
                .Failure(validationError));

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.InvalidScope, error.Error);
        Assert.Equal("Invalid scope requested", error.ErrorDescription);
        _fetcher.Verify(f => f.FetchAsync(request), Times.Once);
        _validator.Verify(v => v.ValidateAsync(fetchedRequest), Times.Once);
        _processor.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Verifies request passing from fetcher to validator.
    /// Fetched request should be validated, not original request.
    /// Critical for PAR and request object support.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldPassFetchedRequestToValidator()
    {
        // Arrange
        var originalRequest = CreateRequest();
        var fetchedRequest = new AuthorizationRequest
        {
            ClientId = "client_123",
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            State = "modified_state",
        };
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            ClientInfo = new ClientInfo("client_123"),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(fetchedRequest, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, fetchedRequest.RedirectUri);

        _fetcher
            .Setup(f => f.FetchAsync(originalRequest))
            .ReturnsAsync(Result<AuthorizationRequest, AuthorizationRequestValidationError>
                .Success(fetchedRequest));

        _validator
            .Setup(v => v.ValidateAsync(It.Is<AuthorizationRequest>(r => r.State == "modified_state")))
            .ReturnsAsync(Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>
                .Success(validRequest));

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(processedResponse);

        // Act
        await _handler.HandleAsync(originalRequest);

        // Assert
        _validator.Verify(v => v.ValidateAsync(
            It.Is<AuthorizationRequest>(r => r.State == "modified_state")), Times.Once);
    }

    /// <summary>
    /// Verifies metadata indicates request parameter support.
    /// Per JAR (RFC 9101), request parameter should be advertised.
    /// </summary>
    [Fact]
    public void Metadata_ShouldIndicateRequestParameterSupported()
    {
        // Act
        var metadata = _handler.Metadata;

        // Assert
        Assert.True(metadata.RequestParameterSupported);
    }

    /// <summary>
    /// Verifies metadata indicates claims parameter support.
    /// Per OIDC Core Section 5.5, claims parameter support should be advertised.
    /// </summary>
    [Fact]
    public void Metadata_ShouldIndicateClaimsParameterSupported()
    {
        // Act
        var metadata = _handler.Metadata;

        // Assert
        Assert.True(metadata.ClaimsParameterSupported);
    }

    /// <summary>
    /// Verifies grant types supported includes implicit.
    /// Per OIDC Core, authorization endpoint supports implicit grant.
    /// </summary>
    [Fact]
    public void GrantTypesSupported_ShouldIncludeImplicit()
    {
        // Act
        var grantTypes = _handler.GrantTypesSupported.ToArray();

        // Assert
        Assert.Contains(GrantTypes.Implicit, grantTypes);
    }

    /// <summary>
    /// Verifies error response includes error code.
    /// Per OAuth 2.0, error responses MUST include error parameter.
    /// </summary>
    [Fact]
    public async Task HandleAsync_OnError_ShouldIncludeErrorCode()
    {
        // Arrange
        var request = CreateRequest();
        var fetchError = new AuthorizationRequestValidationError(
            ErrorCodes.UnauthorizedClient,
            "Client not authorized",
            request.RedirectUri,
            ResponseModes.Query);

        _fetcher
            .Setup(f => f.FetchAsync(request))
            .ReturnsAsync(Result<AuthorizationRequest, AuthorizationRequestValidationError>
                .Failure(fetchError));

        // Act
        var result = await _handler.HandleAsync(request);

        // Assert
        var error = Assert.IsType<AuthorizationError>(result);
        Assert.NotNull(error.Error);
        Assert.NotEmpty(error.Error);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
    }

    /// <summary>
    /// Verifies sequential execution: fetch before validate before process.
    /// Tests that components are called in correct order.
    /// </summary>
    [Fact]
    public async Task HandleAsync_ShouldCallComponentsInOrder()
    {
        // Arrange
        var request = CreateRequest();
        var fetchedRequest = CreateRequest();
        var validationContext = new AuthorizationValidationContext(fetchedRequest)
        {
            ClientInfo = new ClientInfo("client_123"),
        };
        var validRequest = new ValidAuthorizationRequest(validationContext);
        var processedResponse = new AuthorizationError(request, ErrorCodes.ConsentRequired, "",
            ResponseModes.Query, request.RedirectUri);

        var callOrder = new System.Collections.Generic.List<string>();

        _fetcher
            .Setup(f => f.FetchAsync(request))
            .ReturnsAsync(() =>
            {
                callOrder.Add("fetch");
                return Result<AuthorizationRequest, AuthorizationRequestValidationError>
                    .Success(fetchedRequest);
            });

        _validator
            .Setup(v => v.ValidateAsync(fetchedRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("validate");
                return Result<ValidAuthorizationRequest, AuthorizationRequestValidationError>
                    .Success(validRequest);
            });

        _processor
            .Setup(p => p.ProcessAsync(validRequest))
            .ReturnsAsync(() =>
            {
                callOrder.Add("process");
                return processedResponse;
            });

        // Act
        await _handler.HandleAsync(request);

        // Assert
        Assert.Equal(3, callOrder.Count);
        Assert.Equal("fetch", callOrder[0]);
        Assert.Equal("validate", callOrder[1]);
        Assert.Equal("process", callOrder[2]);
    }
}
