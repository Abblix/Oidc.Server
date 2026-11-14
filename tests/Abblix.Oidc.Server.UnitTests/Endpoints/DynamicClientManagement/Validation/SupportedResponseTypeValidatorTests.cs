// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Locks <see cref="SupportedResponseTypeValidator"/> against the registration-time gap
/// it exists to close: client registration must surface
/// <c>invalid_client_metadata</c> when <c>response_types</c> include parts the server has
/// no processor for, instead of letting the client fail with <c>unsupported_response_type</c>
/// on its first authorization request.
/// </summary>
public class SupportedResponseTypeValidatorTests
{
    private static IAuthorizationResponseBuilder Processor(string responseType) =>
        Mock.Of<IAuthorizationResponseBuilder>(p => p.ResponseType == responseType);

    private static IAuthorizationResponseBuilder[] CodeOnly =>
        [Processor(ResponseTypes.Code)];

    private static IAuthorizationResponseBuilder[] CodeTokenIdToken =>
    [
        Processor(ResponseTypes.Code),
        Processor(ResponseTypes.Token),
        Processor(ResponseTypes.IdToken),
    ];

    private static ClientRegistrationValidationContext Context(string[][] responseTypes)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = responseTypes,
        };
        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// FAPI 2.0 Message Signing section 5.3.3, response_modes: "If omitted, the default is that the client may use any
    /// of the response modes supported by the authorization server". Omitted, or listing supported modes, it passes; a
    /// mode the server does not support, or an empty list admitting none, is refused.
    /// </summary>
    [Theory]
    [InlineData(null, null)]
    [InlineData(new[] { ResponseModes.QueryJwt, ResponseModes.FormPost }, null)]
    [InlineData(new[] { ResponseModes.Jwt, "web_message" }, ErrorCodes.InvalidClientMetadata)]
    [InlineData(new string[0], ErrorCodes.InvalidClientMetadata)]
    public async Task ValidateAsync_ResponseModes_AreThoseTheServerSupports(string[]? responseModes, string? expected)
    {
        var validator = Validator(CodeOnly);
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseModes = responseModes,
        });

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(expected, result?.Error);
    }

    /// <summary>
    /// The response modes are judged against the list discovery publishes, which a host may replace: under a host
    /// whose metadata provider advertises only query, query.jwt is refused and query admitted.
    /// </summary>
    [Theory]
    [InlineData(ResponseModes.QueryJwt, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ResponseModes.Query, null)]
    public async Task ValidateAsync_ResponseModes_AreThoseTheReplacedProviderPublishes(string responseMode, string? expected)
    {
        var metadata = Mock.Of<IAuthorizationMetadataProvider>(
            provider => provider.ResponseModesSupported == new[] { ResponseModes.Query });
        var validator = new SupportedResponseTypeValidator(CodeOnly, metadata);
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseModes = [responseMode],
        });

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(expected, result?.Error);
    }

    /// <summary>
    /// The validator over the metadata discovery publishes by default for <paramref name="processors"/>.
    /// </summary>
    private static SupportedResponseTypeValidator Validator(IAuthorizationResponseBuilder[] processors)
        => new(processors, new AuthorizationMetadataProvider(processors));

    /// <summary>
    /// Default registration (no <c>EnableImplicitFlow()</c>) advertises only the Code Flow.
    /// A client registering exactly that combination must pass.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeOnlyServer_AcceptsCodeRegistration()
    {
        var validator = Validator(CodeOnly);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([[ResponseTypes.Code]]));

        Assert.Null(result);
    }

    /// <summary>
    /// Without <c>EnableImplicitFlow()</c>, a client requesting <c>token</c> must be rejected
    /// at registration time - the gap this validator closes.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Token)]
    [InlineData(ResponseTypes.IdToken)]
    public async Task ValidateAsync_CodeOnlyServer_RejectsImplicitResponseType(string unsupportedPart)
    {
        var validator = Validator(CodeOnly);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([[unsupportedPart]]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(unsupportedPart, result.ErrorDescription);
    }

    /// <summary>
    /// Hybrid combinations are rejected when any single part lacks a processor: the failure
    /// of one part disqualifies the whole combination.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeOnlyServer_RejectsHybridContainingUnsupportedPart()
    {
        var validator = Validator(CodeOnly);

        var result = await validator.ValidateAsync(
            SingleIssuer.Tenant,
            Context([[ResponseTypes.Code, ResponseTypes.IdToken]]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(ResponseTypes.IdToken, result.ErrorDescription);
    }

    /// <summary>
    /// With <c>EnableImplicitFlow()</c> all three response-type parts are registered, so any
    /// canonical combination - including pure Implicit and full Hybrid - must be accepted.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Code)]
    [InlineData(ResponseTypes.Token)]
    [InlineData(ResponseTypes.IdToken)]
    public async Task ValidateAsync_FullServer_AcceptsAnySingleResponseType(string responseType)
    {
        var validator = Validator(CodeTokenIdToken);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([[responseType]]));

        Assert.Null(result);
    }

    /// <summary>
    /// Client registering several combinations at once is rejected if any single combination
    /// references an unsupported part - registrations are all-or-nothing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeOnlyServer_RejectsMultiCombinationContainingUnsupported()
    {
        var validator = Validator(CodeOnly);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([
            [ResponseTypes.Code],
            [ResponseTypes.Token],
        ]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(ResponseTypes.Token, result.ErrorDescription);
    }

    /// <summary>
    /// An empty string among the response types names none, so it is refused rather than registered as a
    /// combination no authorization request can match.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyResponseType_IsRefusedAsInvalidClientMetadata()
    {
        var validator = Validator(CodeTokenIdToken);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([[ResponseTypes.Code], []]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Empty <c>response_types</c> array - nothing to validate against - passes the gate
    /// (other validators handle the «must be specified» rule, this one is purely about
    /// support).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyResponseTypes_Passes()
    {
        var validator = Validator(CodeTokenIdToken);

        var result = await validator.ValidateAsync(SingleIssuer.Tenant, Context([]));

        Assert.Null(result);
    }
}
