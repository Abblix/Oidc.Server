// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// A JARM response the server cannot produce - the client asked for its responses encrypted and publishes no key a
/// token can be encrypted to - is answered on the client's redirect URI with unauthorized_client, in the plain mode
/// the JARM mode delivers through (RFC 6749 section 4.1.2.1), the state kept, rather than failing as a server error.
/// </summary>
public class AuthorizationResponseEncoderTests
{
    private const string State = "af0ifjsldkj";

    [Theory]
    [InlineData(ResponseModes.QueryJwt, ResponseModes.Query)]
    [InlineData(ResponseModes.FragmentJwt, ResponseModes.Fragment)]
    [InlineData(ResponseModes.FormPostJwt, ResponseModes.FormPost)]
    [InlineData(ResponseModes.Jwt, ResponseModes.Query)]
    public async Task AResponseJwtTheClientCannotReceive_IsAnsweredWithUnauthorizedClientInThePlainMode(
        string responseMode, string deliveryMode)
    {
        var model = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            State = State,
        };
        var success = new SuccessfullyAuthenticated(model, responseMode, "session", [])
        {
            Code = "code",
            SessionPersistence = Abblix.Oidc.Server.Features.UserAuthentication.SessionPersistence.BrowserSession,
        };

        var encoded = await Encoder(Refusing()).EncodeAsync(SingleIssuer.Tenant, success);

        var error = Assert.IsType<AuthorizationError>(encoded);
        Assert.Equal(ErrorCodes.UnauthorizedClient, error.Error);
        Assert.Equal(deliveryMode, error.ResponseMode);
        Assert.Null(error.ResponseJwt);
        Assert.Equal(TestConstants.DefaultRedirectUri, error.RedirectUri);
        Assert.Equal(State, error.Model.State);
    }

    /// <summary>
    /// An error response that cannot be packed into a JWT either is still the error the request earned, delivered in
    /// the plain mode.
    /// </summary>
    [Fact]
    public async Task AnErrorTheClientCannotReceiveAsAJwt_IsDeliveredInThePlainMode()
    {
        var model = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            State = State,
        };
        var refusal = new AuthorizationError(
            model, ErrorCodes.AccessDenied, "denied", ResponseModes.QueryJwt, TestConstants.DefaultRedirectUri);

        var encoded = await Encoder(Refusing()).EncodeAsync(SingleIssuer.Tenant, refusal);

        var error = Assert.IsType<AuthorizationError>(encoded);
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        Assert.Equal(ResponseModes.Query, error.ResponseMode);
        Assert.Null(error.ResponseJwt);
    }

    private static IResponseJwtBuilder Refusing()
    {
        var builder = new Mock<IResponseJwtBuilder>(MockBehavior.Strict);
        builder
            .Setup(b => b.BuildAsync(
                It.IsAny<TenantDefinition>(),
                TestConstants.DefaultClientId,
                It.IsAny<IReadOnlyList<(string name, string? value)>>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidClient, "no usable key"));
        return builder.Object;
    }

    private static AuthorizationResponseEncoder Encoder(IResponseJwtBuilder builder)
    {
        var metadata = new Mock<IAuthorizationMetadataProvider>(MockBehavior.Strict);
        metadata.SetupGet(m => m.AuthorizationResponseIssParameterSupported).Returns(false);
        return new AuthorizationResponseEncoder(metadata.Object, builder);
    }
}
