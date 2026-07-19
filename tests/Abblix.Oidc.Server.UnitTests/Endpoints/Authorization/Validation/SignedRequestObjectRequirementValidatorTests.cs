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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="SignedRequestObjectRequirementValidator"/> verifying the
/// RFC 9101 §10.5 require_signed_request_object client metadata: plain-parameter requests from a
/// committed client are rejected, while request-object and PAR-originated requests pass.
/// </summary>
public class SignedRequestObjectRequirementValidatorTests
{
    private readonly SignedRequestObjectRequirementValidator _validator = new();

    private static AuthorizationValidationContext CreateContext(
        bool requireSignedRequestObject,
        string? requestObject = null,
        Uri? pushedRequestUri = null)
    {
        var request = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
            Request = requestObject,
            PushedRequestUri = pushedRequestUri,
        };

        return new AuthorizationValidationContext(request)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId)
            {
                RequireSignedRequestObject = requireSignedRequestObject,
            },
        };
    }

    [Fact]
    public async Task ValidateAsync_FlaggedClientWithPlainParameters_ReturnsError()
    {
        var context = CreateContext(requireSignedRequestObject: true);

        var result = await _validator.ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
    }

    [Fact]
    public async Task ValidateAsync_FlaggedClientWithRequestObject_Passes()
    {
        var context = CreateContext(requireSignedRequestObject: true, requestObject: "header.payload.signature");

        Assert.Null(await _validator.ValidateAsync(context));
    }

    /// <summary>
    /// A PAR-stored request already went through this validator at push time, so the
    /// authorize-time pass must not reject it again.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_FlaggedClientWithPushedRequest_Passes()
    {
        var context = CreateContext(
            requireSignedRequestObject: true,
            pushedRequestUri: new Uri("urn:ietf:params:oauth:request_uri:abc"));

        Assert.Null(await _validator.ValidateAsync(context));
    }

    [Fact]
    public async Task ValidateAsync_UnflaggedClientWithPlainParameters_Passes()
    {
        var context = CreateContext(requireSignedRequestObject: false);

        Assert.Null(await _validator.ValidateAsync(context));
    }
}
