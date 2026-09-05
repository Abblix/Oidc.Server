// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
