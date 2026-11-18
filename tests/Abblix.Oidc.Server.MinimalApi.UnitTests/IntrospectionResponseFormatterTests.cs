// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// How the introspection endpoint answers a JWT response (RFC 9701) it cannot produce for the client.
/// </summary>
/// <remarks>
/// The twin of the MVC suite's <c>IntrospectionResponseFormatterTests</c>.
/// </remarks>
public class IntrospectionResponseFormatterTests
{
    private static readonly TenantDefinition Served = new() { Id = "main", Issuer = new Uri("https://auth.example.com") };

    /// <summary>Tells every request it is served by <paramref name="tenant"/>.</summary>
    private sealed class ServedBy(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }

    /// <summary>
    /// A client that registered introspection_encrypted_response_alg and has no key it can be encrypted to under it is
    /// refused the JWT as unauthorized_client with HTTP 400 (RFC 6749 section 5.2), and the plain document is not
    /// sent in its place, though the caller accepts it too.
    /// </summary>
    [Theory]
    [InlineData(MediaTypes.TokenIntrospectionJwt)]
    [InlineData(MediaTypes.TokenIntrospectionJwt + ", " + System.Net.Mime.MediaTypeNames.Application.Json)]
    public async Task A_client_that_cannot_be_encrypted_to_is_refused_the_response(string accept)
    {
        var clientJwtFormatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        clientJwtFormatter
            .Setup(f => f.FormatAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()))
            .ReturnsAsync(new OidcError(ErrorCodes.UnauthorizedClient, "no key to encrypt to"));
        var signingKeys = Mock.Of<IAuthServiceKeysProvider>(provider =>
            provider.GetSigningKeys(It.IsAny<TenantDefinition>(), It.IsAny<bool>()) ==
            new JsonWebKey[] { JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, null, 2048) }.ToAsyncEnumerable());

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Accept = accept;
        var formatter = new IntrospectionResponseFormatter(
            new ServedBy(Served),
            new IntrospectionResponseJwtBuilder(
                clientJwtFormatter.Object, TimeProvider.System, signingKeys,
                Abblix.Oidc.Server.UnitTests.TestInfrastructure.TestSigningAlgorithms.Registered),
            Mock.Of<IHttpContextAccessor>(accessor => accessor.HttpContext == httpContext));

        Result<IntrospectionSuccess, OidcError> found = new IntrospectionSuccess(
            true,
            new JsonObject { [IanaClaimTypes.Sub] = "user_123" },
            new ClientInfo("client") { IntrospectionSignedResponseAlgorithm = SigningAlgorithms.RS256 });

        var response = await HttpResultRunner.RunAsync(
            await formatter.FormatResponseAsync(new IntrospectionRequest { Token = "token" }, found));

        Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
        Assert.Equal(
            ErrorCodes.UnauthorizedClient,
            JsonNode.Parse(response.Body)![ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
