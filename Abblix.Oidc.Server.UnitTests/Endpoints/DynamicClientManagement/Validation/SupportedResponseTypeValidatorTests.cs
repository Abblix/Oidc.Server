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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
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
    /// Default registration (no <c>EnableImplicitFlow()</c>) advertises only the Code Flow.
    /// A client registering exactly that combination must pass.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeOnlyServer_AcceptsCodeRegistration()
    {
        var validator = new SupportedResponseTypeValidator(CodeOnly);

        var result = await validator.ValidateAsync(Context([[ResponseTypes.Code]]));

        Assert.Null(result);
    }

    /// <summary>
    /// Without <c>EnableImplicitFlow()</c>, a client requesting <c>token</c> must be rejected
    /// at registration time — the gap this validator closes.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Token)]
    [InlineData(ResponseTypes.IdToken)]
    public async Task ValidateAsync_CodeOnlyServer_RejectsImplicitResponseType(string unsupportedPart)
    {
        var validator = new SupportedResponseTypeValidator(CodeOnly);

        var result = await validator.ValidateAsync(Context([[unsupportedPart]]));

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
        var validator = new SupportedResponseTypeValidator(CodeOnly);

        var result = await validator.ValidateAsync(
            Context([[ResponseTypes.Code, ResponseTypes.IdToken]]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(ResponseTypes.IdToken, result.ErrorDescription);
    }

    /// <summary>
    /// With <c>EnableImplicitFlow()</c> all three response-type parts are registered, so any
    /// canonical combination — including pure Implicit and full Hybrid — must be accepted.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Code)]
    [InlineData(ResponseTypes.Token)]
    [InlineData(ResponseTypes.IdToken)]
    public async Task ValidateAsync_FullServer_AcceptsAnySingleResponseType(string responseType)
    {
        var validator = new SupportedResponseTypeValidator(CodeTokenIdToken);

        var result = await validator.ValidateAsync(Context([[responseType]]));

        Assert.Null(result);
    }

    /// <summary>
    /// Client registering several combinations at once is rejected if any single combination
    /// references an unsupported part — registrations are all-or-nothing.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_CodeOnlyServer_RejectsMultiCombinationContainingUnsupported()
    {
        var validator = new SupportedResponseTypeValidator(CodeOnly);

        var result = await validator.ValidateAsync(Context([
            [ResponseTypes.Code],
            [ResponseTypes.Token],
        ]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(ResponseTypes.Token, result.ErrorDescription);
    }

    /// <summary>
    /// Empty <c>response_types</c> array — nothing to validate against — passes the gate
    /// (other validators handle the «must be specified» rule, this one is purely about
    /// support).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyResponseTypes_Passes()
    {
        var validator = new SupportedResponseTypeValidator(CodeTokenIdToken);

        var result = await validator.ValidateAsync(Context([]));

        Assert.Null(result);
    }
}
