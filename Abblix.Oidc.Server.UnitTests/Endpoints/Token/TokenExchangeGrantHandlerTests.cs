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
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenExchangeGrantHandler"/> -- RFC 8693 Token Exchange. After slice 2
/// the handler dispatches per-format subject token validation through keyed
/// <see cref="ISubjectTokenResolver"/> registrations; these tests stub the resolver via
/// in-memory DI and assert the handler's pipeline (allowlist, actor rejection, dispatch,
/// grant assembly) without involving JWT validation.
/// </summary>
public class TokenExchangeGrantHandlerTests
{
    private const string ClientId = "test-client";
    private const string SubjectTokenWire = "header.payload.signature";
    private const string TestSubject = "user-7";
    private const string TestSessionId = "test-session";

    private readonly Mock<IParameterValidator> _parameterValidator = new(MockBehavior.Strict);
    private readonly Mock<ISessionIdGenerator> _sessionIdGenerator = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();

    public TokenExchangeGrantHandlerTests()
    {
        _sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns(TestSessionId);
    }

    [Fact]
    public async Task ValidSubjectToken_DispatchedToTypedResolver_ReturnsAuthorizedGrant()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: "https://issuer", Scope: ["openid"], AuthorizationDetailsRaw: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);
    }

    [Fact]
    public async Task SubjectTokenAuthorizationDetails_ForwardedToContext_ByteExact()
    {
        const string adWire = """[{"type":"payment_initiation","actions":["initiate"]}]""";
        var adNode = (JsonArray)JsonNode.Parse(adWire)!;
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetailsRaw: adNode);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.AuthorizationDetails);
        Assert.Equal(adWire, grant.Context.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task UnregisteredSubjectTokenType_RejectsWithInvalidRequest()
    {
        // No resolver registered for the request's type. ALLOWLIST is null so the per-client
        // check passes through, but the keyed lookup at the resolver step fails.
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(null);
        var request = ExchangeRequest("urn:ietf:params:oauth:token-type:saml2");

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("saml2", error.ErrorDescription);
        Assert.Contains("not supported", error.ErrorDescription);
    }

    [Fact]
    public async Task EmptyAllowlist_RejectsEveryRequest()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist();  // empty -> deny-all
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("not permitted", error.ErrorDescription);
    }

    [Fact]
    public async Task SubjectTokenTypeNotInAllowlist_Rejected()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.IdToken);  // only id_token allowed
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allowlist", error.ErrorDescription);
    }

    [Fact]
    public async Task ActorTokenPresent_RejectedAsNotYetSupported()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = "actor.jwt.signature",
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,
        };

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("Delegation", error.ErrorDescription);
    }

    [Fact]
    public async Task ResolverFailure_Propagated()
    {
        // Resolver returns an OidcError -- the handler propagates it without rewrapping so
        // resolver-specific failure descriptions reach the wire client (RFC 8693 §2.2.2 maps
        // every error to invalid_request at the wire, but the description preserves diagnostic
        // detail).
        var (handler, resolverMock) = CreateHandlerWithResolverMock(TokenExchangeTokenTypes.AccessToken);
        resolverMock
            .Setup(r => r.ResolveAsync(SubjectTokenWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidRequest, "subject expired"));
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("subject expired", error.ErrorDescription);
    }

    [Fact]
    public async Task ClientWithNullAllowlist_AcceptsAnyResolvedTokenType()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetailsRaw: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.IdToken, ctx);
        var clientInfo = ClientWithAllowlist(null);  // tri-state: no constraint
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken);

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
    }

    [Fact]
    public async Task RequestScope_OverridesSubjectScope()
    {
        var subjectScope = new[] { "openid", "profile", "email" };
        var requestScope = new[] { "openid" };  // narrow to one
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: subjectScope, AuthorizationDetailsRaw: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = requestScope };

        SetupRequiredOnly(request);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(requestScope, grant.Context.Scope);
    }

    // ──── helpers ────

    private (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock) CreateHandlerWith(
        string tokenType, SubjectTokenContext resolvedContext)
    {
        var (handler, resolverMock) = CreateHandlerWithResolverMock(tokenType);
        resolverMock
            .Setup(r => r.ResolveAsync(SubjectTokenWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(resolvedContext);
        return (handler, resolverMock);
    }

    private (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock)
        CreateHandlerWithResolverMock(string tokenType)
    {
        var resolverMock = new Mock<ISubjectTokenResolver>(MockBehavior.Strict);
        resolverMock.SetupGet(r => r.Type).Returns(tokenType);

        var services = new ServiceCollection();
        services.AddKeyedSingleton(tokenType, resolverMock.Object);
        var sp = services.BuildServiceProvider();

        var handler = new TokenExchangeGrantHandler(
            _parameterValidator.Object, sp, _sessionIdGenerator.Object, _timeProvider);
        return (handler, resolverMock);
    }

    private TokenExchangeGrantHandler CreateHandlerWithoutResolvers()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        return new TokenExchangeGrantHandler(
            _parameterValidator.Object, sp, _sessionIdGenerator.Object, _timeProvider);
    }

    private void SetupRequiredOnly(TokenRequest request)
    {
        _parameterValidator.Setup(v => v.Required(request.SubjectToken, nameof(request.SubjectToken)));
        _parameterValidator.Setup(v => v.Required(request.SubjectTokenType, nameof(request.SubjectTokenType)));
    }

    private static ClientInfo ClientWithAllowlist(params string[]? allowlist) =>
        new(ClientId) { TokenExchangeAllowedSubjectTokenTypes = allowlist };

    private static TokenRequest ExchangeRequest(string subjectTokenType) => new()
    {
        GrantType = GrantTypes.TokenExchange,
        SubjectToken = SubjectTokenWire,
        SubjectTokenType = subjectTokenType,
    };
}
