// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

/// <summary>
/// The code builder reserves the request's code_challenge and nonce before it issues a code, and a value the client
/// already used refuses the code rather than following it.
/// </summary>
public class AuthorizationCodeBuilderTests
{
    private const string ClientId = TestConstants.DefaultClientId;
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Nonce = "n-0S6_WzA2Mj";
    private const string Code = "the-code";

    // Strict, so a code issued for a refused request fails the test that refuses it
    private readonly Mock<IAuthorizationCodeService> _codes = new(MockBehavior.Strict);
    private readonly Mock<IAuthorizationValueReuseDetector> _reuse = new(MockBehavior.Strict);

    [Theory]
    [InlineData(AuthorizationRequest.Parameters.CodeChallenge)]
    [InlineData(AuthorizationRequest.Parameters.Nonce)]
    public async Task AValueAlreadyUsed_RefusesTheCode(string reusedKind)
    {
        _reuse
            .Setup(d => d.TryReserveAsync(TestTenant.Matched, ClientId, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((TenantDefinition _, string _, string kind, string _) => kind != reusedKind);
        var (request, grant, result) = Arrange();

        var refusal = await Builder().BuildResponseAsync(SingleIssuer.Tenant, request, grant, result);

        Assert.Equal(ErrorCodes.InvalidRequest, refusal?.Error);
        Assert.Null(result.Code);
    }

    [Fact]
    public async Task FreshValues_IssueTheCode()
    {
        _reuse
            .Setup(d => d.TryReserveAsync(TestTenant.Matched, ClientId, It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(true);
        var (request, grant, result) = Arrange();
        _codes
            .Setup(s => s.GenerateAuthorizationCodeAsync(TestTenant.Matched, grant, It.IsAny<TimeSpan>()))
            .ReturnsAsync(Code);

        var refusal = await Builder().BuildResponseAsync(SingleIssuer.Tenant, request, grant, result);

        Assert.Null(refusal);
        Assert.Equal(Code, result.Code);
        _reuse.Verify(
            d => d.TryReserveAsync(TestTenant.Matched, ClientId, AuthorizationRequest.Parameters.CodeChallenge, CodeChallenge),
            Times.Once);
        _reuse.Verify(
            d => d.TryReserveAsync(TestTenant.Matched, ClientId, AuthorizationRequest.Parameters.Nonce, Nonce),
            Times.Once);
    }

    /// <summary>
    /// An empty nonce is no nonce, as the nonce validator reads it, so it is never reserved and a client sending one
    /// on every request is not refused for repeating it.
    /// </summary>
    [Fact]
    public async Task AnEmptyNonce_IsNotReserved()
    {
        _reuse
            .Setup(d => d.TryReserveAsync(
                TestTenant.Matched, ClientId, AuthorizationRequest.Parameters.CodeChallenge, CodeChallenge))
            .ReturnsAsync(true);
        var (request, grant, result) = Arrange();
        grant = grant with { Context = grant.Context with { Nonce = string.Empty } };
        _codes
            .Setup(s => s.GenerateAuthorizationCodeAsync(TestTenant.Matched, grant, It.IsAny<TimeSpan>()))
            .ReturnsAsync(Code);

        Assert.Null(await Builder().BuildResponseAsync(SingleIssuer.Tenant, request, grant, result));
        Assert.Equal(Code, result.Code);
    }

    private AuthorizationCodeBuilder Builder() => new(_codes.Object, _reuse.Object);

    private static (ValidAuthorizationRequest, AuthorizedGrant, SuccessfullyAuthenticated) Arrange()
    {
        var model = new AuthorizationRequest
        {
            ClientId = ClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
        };
        var request = new ValidAuthorizationRequest(
            new AuthorizationValidationContext(model) { ClientInfo = new ClientInfo(ClientId) });

        var grant = new AuthorizedGrant(
            new AuthSession("user_123", "session_123", DateTimeOffset.UnixEpoch, "local"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)
            {
                CodeChallenge = CodeChallenge,
                Nonce = Nonce,
            });

        return (request, grant, new SuccessfullyAuthenticated(model, ResponseModes.Query, "session_123", [])
        {
            SessionPersistence = SessionPersistence.BrowserSession,
        });
    }
}
