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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="FlowTypeValidator"/> verifying flow type detection per OAuth 2.0 and
/// OIDC Core. Tests cover response_type validation, flow detection (authorization code, implicit, hybrid),
/// default response mode assignment, and client-allowed response types.
/// </summary>
public class FlowTypeValidatorTests
{
    private const string ClientId = TestConstants.DefaultClientId;

    private readonly FlowTypeValidator _validator;

    public FlowTypeValidatorTests()
    {
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        // Existing tests exercise Implicit / Hybrid response types; register all three builders so
        // the server-level support gate added in #90 does not pre-reject those scenarios.
        IAuthorizationResponseBuilder[] processors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Code),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Token),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.IdToken),
        ];
        _validator = new FlowTypeValidator(logger.Object, processors, ProfileOptions());
    }

    private static IOptions<OidcOptions> ProfileOptions(
        ClientSecurityProfile defaultSecurityProfile = ClientSecurityProfile.None)
        => Options.Create(new OidcOptions { DefaultSecurityProfile = defaultSecurityProfile });

    /// <summary>
    /// Creates an AuthorizationValidationContext for testing.
    /// </summary>
    private static AuthorizationValidationContext CreateContext(
        string[]? responseType,
        string[][]? allowedResponseTypes = null,
        string? responseMode = null,
        ClientSecurityProfile? securityProfile = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = responseType,
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            ResponseMode = responseMode,
        };

        var clientInfo = new ClientInfo(ClientId)
        {
            AllowedResponseTypes = allowedResponseTypes ?? [[ResponseTypes.Code]],
            SecurityProfile = securityProfile,
        };

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = clientInfo,
        };
    }

    /// <summary>
    /// Verifies that ValidateAsync detects authorization code flow correctly.
    /// Per OAuth 2.0, response_type=code indicates authorization code flow.
    /// Default response mode should be query.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeResponseType_ShouldDetectAuthorizationCodeFlow()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Code], [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.AuthorizationCode, context.FlowType);
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects implicit flow for id_token response type.
    /// Per OIDC Core 1.0 Section 3.2, response_type=id_token is implicit flow.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenResponseType_ShouldDetectImplicitFlow()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.IdToken], [[ResponseTypes.IdToken]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects implicit flow for token response type.
    /// Per OAuth 2.0 Section 4.2, response_type=token is implicit grant.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenResponseType_ShouldDetectImplicitFlow()
    {
        // Arrange
        var context = CreateContext([ResponseTypes.Token], [[ResponseTypes.Token]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects implicit flow for id_token token.
    /// Per OIDC Core 1.0, response_type=id_token token is implicit flow.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_IdTokenTokenResponseType_ShouldDetectImplicitFlow()
    {
        // Arrange
        var context = CreateContext(
            [ResponseTypes.IdToken, ResponseTypes.Token],
            [[ResponseTypes.IdToken, ResponseTypes.Token]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects hybrid flow for code id_token.
    /// Per OIDC Core 1.0 Section 3.3, response_type=code id_token is hybrid flow.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeIdTokenResponseType_ShouldDetectHybridFlow()
    {
        // Arrange
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.IdToken],
            [[ResponseTypes.Code, ResponseTypes.IdToken]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Hybrid, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects hybrid flow for code token.
    /// Per OAuth 2.0 hybrid flow extensions, response_type=code token is hybrid.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeTokenResponseType_ShouldDetectHybridFlow()
    {
        // Arrange
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.Token],
            [[ResponseTypes.Code, ResponseTypes.Token]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Hybrid, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync detects hybrid flow for code id_token token.
    /// Per OIDC Core 1.0, response_type=code id_token token is hybrid flow.
    /// Default response mode should be fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeIdTokenTokenResponseType_ShouldDetectHybridFlow()
    {
        // Arrange
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token],
            [[ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Hybrid, context.FlowType);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects null response_type.
    /// Per RFC 6749 §4.1.2.1, response_type is REQUIRED and a missing required parameter
    /// is invalid_request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NullResponseType_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(null, [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Equal(ResponseModes.Query, context.ResponseMode); // Default fallback
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects empty response_type array.
    /// Per RFC 6749 §4.1.2.1, an absent required parameter is invalid_request.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyResponseType_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext([], [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects unknown response_type values.
    /// Per OAuth 2.0, only registered response types are valid.
    /// Critical for preventing unsupported flow types.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UnknownResponseType_ShouldReturnError()
    {
        // Arrange
        var context = CreateContext(["unknown"], [["unknown"]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
        Assert.Contains("not supported", result.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects response_type not allowed by client.
    /// Per RFC 6749 §4.1.2.1 / §4.2.2.1 this is unauthorized_client (the server supports the
    /// method, this client is not registered for it), and per OAuth 2.0 Multiple Response Types §5
    /// the error for a fragment-encoded response_type must travel in the fragment.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseTypeNotAllowedForClient_ShouldReturnError()
    {
        // Arrange - Client registered for code, but requesting id_token
        var context = CreateContext([ResponseTypes.IdToken], [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync accepts response_type matching client configuration.
    /// Client registered for multiple response types should accept any registered type.
    /// Tests flexible client configuration support.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseTypeMatchesClientConfiguration_ShouldSucceed()
    {
        // Arrange - Client registered for both code and id_token
        var context = CreateContext(
            [ResponseTypes.IdToken],
            [[ResponseTypes.Code], [ResponseTypes.IdToken]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
    }

    /// <summary>
    /// Verifies that ValidateAsync validates response_type component order insensitively.
    /// Per OIDC Core, response_type components can be in any order.
    /// Tests that [code, id_token] and [id_token, code] are equivalent.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseTypeInDifferentOrder_ShouldSucceed()
    {
        // Arrange - Request has [token, id_token], client allows [id_token, token]
        var context = CreateContext(
            [ResponseTypes.Token, ResponseTypes.IdToken],
            [[ResponseTypes.IdToken, ResponseTypes.Token]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects an uppercase <c>response_type</c> at the server-level
    /// support gate. RFC 6749 §3.1.1 declares <c>response_type</c> values case-sensitive; the
    /// server-level part check (introduced with the Implicit Flow opt-in in #90) compares each
    /// part against registered <see cref="IAuthorizationResponseBuilder"/> instances using
    /// <see cref="StringComparer.Ordinal"/>, so <c>CODE</c> does not match the registered
    /// <c>code</c> processor and the request is rejected with <c>unsupported_response_type</c>
    /// before reaching the historically tolerant HasFlag-based flow detection.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UppercaseResponseType_ShouldFailServerLevelSupportGate()
    {
        // Arrange - Client configured for uppercase "CODE"
        var context = CreateContext(["CODE"], [["CODE"]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
    }

    /// <summary>
    /// Verifies that without <c>EnableImplicitFlow()</c> the validator rejects requests asking for
    /// the <c>token</c> response type with <c>unsupported_response_type</c>, even when the client
    /// is configured to allow it. The server-level support gate (registered processors) takes
    /// precedence over the client-level <c>AllowedResponseTypes</c> whitelist — per OAuth 2.1 §1.4
    /// the Implicit Grant is deprecated and the library default refuses to issue access tokens
    /// directly from the authorization endpoint.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Token)]
    [InlineData(ResponseTypes.IdToken)]
    public async Task ValidateAsync_ImplicitResponseType_WhenImplicitFlowDisabled_FailsWithUnsupportedResponseType(
        string implicitResponseType)
    {
        // Arrange — only Code processor registered (default, no EnableImplicitFlow)
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        IAuthorizationResponseBuilder[] codeOnlyProcessors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(p => p.ResponseType == ResponseTypes.Code),
        ];
        var validator = new FlowTypeValidator(logger.Object, codeOnlyProcessors, ProfileOptions());

        // Client is configured to allow the implicit response type, so without the server-level
        // gate the request would proceed past ResponseTypeAllowed.
        var context = CreateContext([implicitResponseType], [[implicitResponseType]]);

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
    }

    /// <summary>
    /// Same as the single-part case but for the four hybrid combinations: <c>code token</c>,
    /// <c>code id_token</c>, <c>token id_token</c>, and <c>code token id_token</c>. Each one
    /// contains at least one part (<c>token</c> or <c>id_token</c>) that has no registered
    /// processor when Implicit Flow is disabled, so the validator rejects the entire request.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Code, ResponseTypes.Token)]
    [InlineData(ResponseTypes.Code, ResponseTypes.IdToken)]
    [InlineData(ResponseTypes.Token, ResponseTypes.IdToken)]
    [InlineData(ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken)]
    public async Task ValidateAsync_HybridResponseType_WhenImplicitFlowDisabled_FailsWithUnsupportedResponseType(
        params string[] hybridResponseType)
    {
        // Arrange — only Code processor registered.
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        IAuthorizationResponseBuilder[] codeOnlyProcessors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(p => p.ResponseType == ResponseTypes.Code),
        ];
        var validator = new FlowTypeValidator(logger.Object, codeOnlyProcessors, ProfileOptions());

        var context = CreateContext(hybridResponseType, [hybridResponseType]);

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles duplicate response_type values.
    /// HashSet deduplication means [code, code] is treated as [code].
    /// Tests that duplicate values don't cause validation errors.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_DuplicateResponseType_ShouldSucceedAfterDeduplication()
    {
        // Arrange - [code, code] becomes [code] via HashSet deduplication
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.Code],
            [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result); // Succeeds after deduplication
        Assert.Equal(FlowTypes.AuthorizationCode, context.FlowType);
    }

    /// <summary>
    /// Verifies that ValidateAsync sets default response mode in error response.
    /// Per OAuth 2.0, error responses must specify response_mode.
    /// Default to query mode for error delivery when not specified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldSetDefaultResponseMode()
    {
        // Arrange
        var context = CreateContext(null, [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync sets default response_mode regardless of request parameter.
    /// FlowTypeValidator always sets default response_mode based on flow type.
    /// Explicit response_mode validation is handled by ResponseModeValidator.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithExplicitResponseMode_ShouldSetDefaultResponseMode()
    {
        // Arrange - Request has explicit response_mode=fragment
        var context = CreateContext(
            [ResponseTypes.Code],
            [[ResponseTypes.Code]],
            responseMode: ResponseModes.Fragment);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.Null(result);
        Assert.Equal(FlowTypes.AuthorizationCode, context.FlowType);
        // FlowTypeValidator always sets default response_mode based on flow type
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync handles multiple allowed response types for client.
    /// Client registered for [code], [id_token], [code id_token] should accept any.
    /// Tests complex client configuration with multiple flow support.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ClientWithMultipleAllowedResponseTypes_ShouldAcceptAll()
    {
        // Arrange - Client supports all three flows
        var allowedResponseTypes = new[]
        {
            new[] { ResponseTypes.Code },
            new[] { ResponseTypes.IdToken },
            new[] { ResponseTypes.Code, ResponseTypes.IdToken },
        };

        // Test authorization code flow
        var context1 = CreateContext([ResponseTypes.Code], allowedResponseTypes);
        var result1 = await _validator.ValidateAsync(context1);
        Assert.Null(result1);
        Assert.Equal(FlowTypes.AuthorizationCode, context1.FlowType);

        // Test implicit flow
        var context2 = CreateContext([ResponseTypes.IdToken], allowedResponseTypes);
        var result2 = await _validator.ValidateAsync(context2);
        Assert.Null(result2);
        Assert.Equal(FlowTypes.Implicit, context2.FlowType);

        // Test hybrid flow
        var context3 = CreateContext([ResponseTypes.Code, ResponseTypes.IdToken], allowedResponseTypes);
        var result3 = await _validator.ValidateAsync(context3);
        Assert.Null(result3);
        Assert.Equal(FlowTypes.Hybrid, context3.FlowType);
    }

    /// <summary>
    /// Verifies that ValidateAsync rejects response_type subset not matching client config.
    /// Client registered for [code id_token] should NOT accept [code] alone.
    /// Tests strict response type matching - all components must match. The code-only request
    /// carries no fragment-encoded value, so the error stays in the query.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ResponseTypeSubsetNotAllowed_ShouldReturnError()
    {
        // Arrange - Client registered for hybrid, requesting code only
        var context = CreateContext(
            [ResponseTypes.Code],
            [[ResponseTypes.Code, ResponseTypes.IdToken]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// OAuth 2.0 Multiple Response Types §5: a rejected hybrid request (contains token) must get
    /// its error in the fragment even when the rejection happens at the server-level support gate.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenBearingResponseTypeRejected_ShouldDefaultErrorModeToFragment()
    {
        // Arrange — only Code processor registered, request asks for code token
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        IAuthorizationResponseBuilder[] codeOnlyProcessors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(p => p.ResponseType == ResponseTypes.Code),
        ];
        var validator = new FlowTypeValidator(logger.Object, codeOnlyProcessors, ProfileOptions());
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.Token],
            [[ResponseTypes.Code, ResponseTypes.Token]]);

        // Act
        var result = await validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
        Assert.Equal(ResponseModes.Fragment, context.ResponseMode);
    }

    /// <summary>
    /// Verifies that ValidateAsync includes error description in error response.
    /// Per OAuth 2.0, error_description is OPTIONAL but RECOMMENDED.
    /// Helps developers diagnose authorization failures.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ErrorResponse_ShouldIncludeErrorDescription()
    {
        // Arrange
        var context = CreateContext(null, [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.ErrorDescription);
        Assert.NotEmpty(result.ErrorDescription);
    }

    /// <summary>
    /// Verifies that ValidateAsync returns error for null response_type.
    /// FlowType intentionally throws when accessed before being set by validator.
    /// Tests clean error handling without setting FlowType.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_OnError_ShouldReturnErrorWithoutSettingFlowType()
    {
        // Arrange
        var context = CreateContext(null, [[ResponseTypes.Code]]);

        // Act
        var result = await _validator.ValidateAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        // Note: Cannot access context.FlowType - it throws when not set
    }

    /// <summary>
    /// Under the FAPI 2.0 profile the authorization-code response type is accepted — the profile
    /// permits exactly this flow.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2CodeResponseType_ShouldSucceed()
    {
        var context = CreateContext(
            [ResponseTypes.Code],
            [[ResponseTypes.Code]],
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.Null(result);
        Assert.Equal(FlowTypes.AuthorizationCode, context.FlowType);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile an implicit or hybrid response type is rejected with
    /// unauthorized_client, even though the client allows it and the server registers the builder —
    /// the profile permits code only, and the granular AllowedResponseTypes whitelist cannot widen it.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.IdToken)]
    [InlineData(ResponseTypes.Token)]
    public async Task ValidateAsync_Fapi2ImplicitResponseType_EvenWhenAllowed_ShouldReturnError(
        string implicitResponseType)
    {
        var context = CreateContext(
            [implicitResponseType],
            [[implicitResponseType]],
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("security profile", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Under the FAPI 2.0 profile a hybrid response type (code + id_token) is rejected: the token-
    /// bearing part is forbidden even though it is combined with code.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2HybridResponseType_ShouldReturnError()
    {
        var context = CreateContext(
            [ResponseTypes.Code, ResponseTypes.IdToken],
            [[ResponseTypes.Code, ResponseTypes.IdToken]],
            securityProfile: ClientSecurityProfile.Fapi2);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("security profile", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    private static FlowTypeValidator AllFlowsValidator(ClientSecurityProfile defaultProfile)
    {
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        IAuthorizationResponseBuilder[] processors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Code),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Token),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.IdToken),
        ];
        return new FlowTypeValidator(logger.Object, processors, ProfileOptions(defaultProfile));
    }

    /// <summary>
    /// A client that states no profile (null) inherits the server-wide DefaultSecurityProfile: a
    /// global FAPI 2.0 default rejects an implicit response type for the unprofiled client.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_GlobalDefaultFapi2_RejectsImplicitForUnprofiledClient()
    {
        var validator = AllFlowsValidator(ClientSecurityProfile.Fapi2);
        var context = CreateContext([ResponseTypes.IdToken], [[ResponseTypes.IdToken]], securityProfile: null);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnauthorizedClient, result.Error);
        Assert.Contains("security profile", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A client that explicitly selects None opts out of a server-wide FAPI 2.0 default: the implicit
    /// response type it is registered for is accepted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ExplicitNoneOverridesGlobalDefaultFapi2_AllowsImplicit()
    {
        var validator = AllFlowsValidator(ClientSecurityProfile.Fapi2);
        var context = CreateContext(
            [ResponseTypes.IdToken],
            [[ResponseTypes.IdToken]],
            securityProfile: ClientSecurityProfile.None);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
        Assert.Equal(FlowTypes.Implicit, context.FlowType);
    }

    private static FlowTypeValidator NoneEnabledValidator()
    {
        var logger = new Mock<ILogger<FlowTypeValidator>>(MockBehavior.Loose);
        IAuthorizationResponseBuilder[] processors =
        [
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Code),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.None),
        ];
        return new FlowTypeValidator(logger.Object, processors, ProfileOptions());
    }

    /// <summary>
    /// With the none response type opted in (its builder registered), <c>response_type=none</c> is
    /// detected as the none flow with the query default response mode (OAuth 2.0 Multiple Response Type
    /// Encoding Practices §4).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoneResponseType_WhenEnabled_ShouldDetectNoneFlow()
    {
        var validator = NoneEnabledValidator();
        var context = CreateContext([ResponseTypes.None], [[ResponseTypes.None]]);

        var result = await validator.ValidateAsync(context);

        Assert.Null(result);
        Assert.Equal(FlowTypes.None, context.FlowType);
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    /// <summary>
    /// OAuth 2.0 Multiple Response Type Encoding Practices §4: <c>none</c> MUST stand alone. A
    /// <c>none code</c> request matches no flow and is rejected with <c>unsupported_response_type</c>,
    /// even though both parts have registered builders.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoneCombinedWithCode_ShouldReturnError()
    {
        var validator = NoneEnabledValidator();
        var context = CreateContext(
            [ResponseTypes.None, ResponseTypes.Code],
            [[ResponseTypes.None, ResponseTypes.Code]]);

        var result = await validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
    }

    /// <summary>
    /// Without <c>EnableNoneFlow()</c> the none processor is absent, so <c>response_type=none</c>
    /// is rejected at the server-level support gate with <c>unsupported_response_type</c> — even when the
    /// client is configured to allow it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoneResponseType_WhenDisabled_FailsWithUnsupportedResponseType()
    {
        // The shared _validator registers only Code/Token/IdToken (no None).
        var context = CreateContext([ResponseTypes.None], [[ResponseTypes.None]]);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.UnsupportedResponseType, result.Error);
    }
}
