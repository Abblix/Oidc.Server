// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Unit tests for <see cref="IntrospectionResponseFormatter"/> verifying RFC 9701 content negotiation: a plain
/// RFC 7662 JSON document unless the client registered <c>introspection_signed_response_alg</c> and requested the
/// JWT media type via <c>Accept</c>, in which case a JWT carrying the <c>token_introspection</c> claim is returned.
/// </summary>
public class IntrospectionResponseFormatterTests
{
    private const string Issuer = "https://auth.example.com";
    private const string ClientId = "test_client";
    private const string EncodedJwt = "header.payload.signature";

    private readonly Mock<IClientJwtFormatter> _clientJwtFormatter = new(MockBehavior.Strict);

    private async Task<ActionResult> FormatAsync(IntrospectionSuccess success, string? acceptHeader)
    {
        var issuerProvider = new Mock<IIssuerProvider>();
        issuerProvider.Setup(p => p.GetIssuer()).Returns(Issuer);

        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());

        var httpContext = new DefaultHttpContext();
        if (acceptHeader != null)
            httpContext.Request.Headers.Accept = acceptHeader;

        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        var formatter = new IntrospectionResponseFormatter(
            issuerProvider.Object,
            _clientJwtFormatter.Object,
            TimeProvider.System,
            options.Object,
            httpContextAccessor.Object);

        Result<IntrospectionSuccess, OidcError> response = success;
        return await formatter.FormatResponseAsync(new IntrospectionRequest { Token = "token" }, response);
    }

    private static IntrospectionSuccess ActiveResponse(string signedResponseAlgorithm) => new(
        true,
        new JsonObject { [IanaClaimTypes.Sub] = "user_123" },
        new ClientInfo(ClientId) { IntrospectionSignedResponseAlgorithm = signedResponseAlgorithm });

    [Fact]
    public async Task FormatResponseAsync_WhenClientHasNoSignedAlgorithm_ReturnsPlainJson()
    {
        var result = await FormatAsync(ActiveResponse(SigningAlgorithms.None), MediaTypes.TokenIntrospectionJwt);

        // RFC 7662 §2.2: active is a JSON boolean, not the string "true".
        var json = Assert.IsType<JsonResult>(result);
        var introspection = Assert.IsType<JsonObject>(json.Value);
        Assert.True(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());

        _clientJwtFormatter.Verify(
            f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()),
            Times.Never);
    }

    [Fact]
    public async Task FormatResponseAsync_WhenTokenInactive_ReturnsBooleanFalse()
    {
        var inactiveResponse = new IntrospectionSuccess(
            false,
            null,
            new ClientInfo(ClientId) { IntrospectionSignedResponseAlgorithm = SigningAlgorithms.None });

        var result = await FormatAsync(inactiveResponse, acceptHeader: null);

        // The dangerous regression case: a string "false" is truthy for lenient JSON consumers, so a revoked
        // token would read as active. The boolean false has no such failure mode.
        var json = Assert.IsType<JsonResult>(result);
        var introspection = Assert.IsType<JsonObject>(json.Value);
        Assert.False(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    [Fact]
    public async Task FormatResponseAsync_WhenClientDidNotRequestJwt_ReturnsPlainJson()
    {
        // The client registered a signing algorithm but did not ask for the JWT media type.
        var result = await FormatAsync(ActiveResponse(SigningAlgorithms.RS256), "application/json");

        Assert.IsType<JsonResult>(result);
        _clientJwtFormatter.Verify(
            f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()),
            Times.Never);
    }

    [Fact]
    public async Task FormatResponseAsync_WhenClientRegisteredAlgAndRequestsJwt_ReturnsJwt()
    {
        JsonWebToken? capturedToken = null;
        _clientJwtFormatter
            .Setup(f => f.FormatAsync(It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()))
            .Callback<JsonWebToken, ClientInfo, ClientJwtEncryption>((token, _, _) => capturedToken = token)
            .ReturnsAsync(EncodedJwt);

        var result = await FormatAsync(ActiveResponse(SigningAlgorithms.RS256), MediaTypes.TokenIntrospectionJwt);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(MediaTypes.TokenIntrospectionJwt, content.ContentType);
        Assert.Equal(EncodedJwt, content.Content);

        // RFC 9701 §5: typ header is the introspection JWT type, signed with the client's algorithm, addressed to
        // the client, and the response carried under the token_introspection claim.
        Assert.NotNull(capturedToken);
        Assert.Equal(JsonWebTokenTypes.TokenIntrospection, capturedToken!.Header.Type);
        Assert.Equal(SigningAlgorithms.RS256, capturedToken.Header.Algorithm);
        Assert.Contains(ClientId, capturedToken.Payload.Audiences);

        var introspection = capturedToken.Payload[IanaClaimTypes.TokenIntrospection]!.AsObject();
        Assert.Equal("user_123", introspection[IanaClaimTypes.Sub]!.GetValue<string>());
        Assert.True(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }
}
