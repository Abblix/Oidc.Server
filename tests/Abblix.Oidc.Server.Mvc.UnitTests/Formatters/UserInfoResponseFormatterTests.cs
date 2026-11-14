// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// The status the UserInfo endpoint, a protected resource, gives each error code RFC 6750 section 3.1 defines.
/// </summary>
/// <remarks>
/// The twin of the Minimal API suite's <c>UserInfoResponseFormatterTests</c>.
/// </remarks>
public class UserInfoResponseFormatterTests
{
    private static async Task<ActionResultRunner.Response> FormatErrorAsync(string errorCode)
    {
        var tenantAccessor = Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext
        {
            Tenant = new TenantDefinition { Id = "main", Issuer = new Uri("https://auth.example.com") },
        });

        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System,
            new Mock<IClientJwtFormatter>(MockBehavior.Strict).Object,
            tenantAccessor,
            new Mock<IOptionsSnapshot<OidcOptions>>(MockBehavior.Strict).Object);

        Result<UserInfoFoundResponse, OidcError> response = new OidcError(errorCode, "the description");
        return await ActionResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), response));
    }

    /// <summary>
    /// RFC 6750 section 3.1, invalid_token: "The access token provided is expired, revoked, malformed, or invalid for
    /// other reasons". A response the token's client cannot be sent, its key set holding only keys its profile forbids,
    /// is answered so with 401 rather than as a server error.
    /// </summary>
    [Fact]
    public async Task A_response_the_clients_key_set_cannot_receive_is_an_invalid_token()
    {
        var tenant = new TenantDefinition { Id = "main", Issuer = new Uri("https://auth.example.com") };
        var tenantAccessor = Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext { Tenant = tenant });
        var client = new ClientInfo("client") { UserInfoSignedResponseAlgorithm = "PS256" };
        var clientJwtFormatter = new Mock<IClientJwtFormatter>();
        clientJwtFormatter
            .Setup(f => f.FormatAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<Abblix.Jwt.JsonWebToken>(), client, It.IsAny<ClientJwtEncryption>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidClient, "the client's key set"));
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System, clientJwtFormatter.Object, tenantAccessor, options.Object);
        Result<UserInfoFoundResponse, OidcError> found =
            new UserInfoFoundResponse(new System.Text.Json.Nodes.JsonObject(), client, tenant.Issuer.OriginalString)
            {
                PresentedScheme = AccessTokenScheme.Bearer,
            };

        var response = await ActionResultRunner.RunAsync(await formatter.FormatResponseAsync(new UserInfoRequest(), found));

        Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
        // RFC 9449 section 7.2: the refusal is answered on the challenge of the scheme the token was presented with
        var challenges = response.Headers[Microsoft.Net.Http.Headers.HeaderNames.WWWAuthenticate]
            .Select(Abblix.Oidc.Server.MinimalApi.UnitTests.ChallengeReader.Parse)
            .ToArray();
        var bearer = Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.Bearer);
        var dpop = Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.DPoP);
        Assert.Equal(ErrorCodes.InvalidToken, bearer.Parameters["error"]);
        Assert.DoesNotContain("error", dpop.Parameters.Keys);
    }

    /// <summary>
    /// RFC 6750 section 3.1: invalid_request is answered with 400, invalid_token with 401. A client answered 401 for
    /// a token sent the way its security profile refuses would renew the token and send it the same way again.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, StatusCodes.Status400BadRequest)]
    [InlineData(ErrorCodes.InvalidToken, StatusCodes.Status401Unauthorized)]
    public async Task An_error_takes_the_status_rfc_6750_gives_its_code(string errorCode, int expectedStatusCode)
    {
        var response = await FormatErrorAsync(errorCode);

        Assert.Equal(expectedStatusCode, response.StatusCode);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3.2: "The response MAY be encrypted without also being signed", and "If the
    /// UserInfo Response is signed and/or encrypted, then the Claims are returned in a JWT". A client that registered
    /// userinfo_encrypted_response_alg alone is answered with a JWT, not the plain document.
    /// </summary>
    [Fact]
    public async Task An_encrypted_only_response_is_a_jwt()
    {
        var tenant = new TenantDefinition { Id = "main", Issuer = new Uri("https://auth.example.com") };
        var tenantAccessor = Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext { Tenant = tenant });
        var client = new ClientInfo("client")
        {
            UserInfoEncryptedResponseAlgorithm = Abblix.Jwt.EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        var clientJwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        clientJwtFormatter
            .Setup(f => f.FormatAsync(
                It.IsAny<TenantDefinition>(),
                It.Is<Abblix.Jwt.JsonWebToken>(token => token.Header.Algorithm == Abblix.Jwt.SigningAlgorithms.None),
                client,
                It.Is<ClientJwtEncryption>(encryption =>
                    encryption.KeyManagementAlgorithm == Abblix.Jwt.EncryptionAlgorithms.KeyManagement.RsaOaep256)))
            .ReturnsAsync("header.encrypted-key.iv.ciphertext.tag");
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var formatter = new UserInfoResponseFormatter(
            TimeProvider.System, clientJwtFormatter.Object, tenantAccessor, options.Object);
        Result<UserInfoFoundResponse, OidcError> found =
            new UserInfoFoundResponse(new System.Text.Json.Nodes.JsonObject(), client, tenant.Issuer.OriginalString);

        var result = await formatter.FormatResponseAsync(new UserInfoRequest(), found);

        var content = Assert.IsType<Microsoft.AspNetCore.Mvc.ContentResult>(result);
        Assert.Equal(MediaTypes.Jwt, content.ContentType);
    }
}
