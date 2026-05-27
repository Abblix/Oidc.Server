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
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenExchangeGrantHandler"/> -- RFC 8693 Token Exchange,
/// slice 1 scope (JWT subject token, impersonation only).
/// </summary>
public class TokenExchangeGrantHandlerTests
{
    private const string ClientId = "test-client";
    private const string SubjectTokenWire = "header.payload.signature";
    private const string TestSubject = "user-7";
    private const string TestSessionId = "test-session";

    private readonly Mock<IParameterValidator> _parameterValidator = new(MockBehavior.Strict);
    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly Mock<ISessionIdGenerator> _sessionIdGenerator = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();
    private readonly TokenExchangeGrantHandler _handler;

    public TokenExchangeGrantHandlerTests()
    {
        _sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns(TestSessionId);
        _handler = new TokenExchangeGrantHandler(
            _parameterValidator.Object,
            _jwtValidator.Object,
            _sessionIdGenerator.Object,
            _timeProvider);
    }

    [Fact]
    public async Task ValidJwtSubjectToken_ReturnsAuthorizedGrant_WithSubjectFromJwt()
    {
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);
        var jwt = TestJwt(subject: TestSubject);

        SetupRequiredAndValidatorOk(request, jwt);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);
    }

    [Fact]
    public async Task SubjectTokenAuthorizationDetails_ForwardedToContext_ByteExact()
    {
        // RFC 8693 + RFC 9396: subject_token's authorization_details must survive into
        // the issued token's AuthorizationContext so a resource server downstream sees
        // the same authorisation set the original token carried.
        const string adWire = """[{"type":"payment_initiation","actions":["initiate"]}]""";
        var adNode = (JsonArray)JsonNode.Parse(adWire)!;

        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);
        var jwt = TestJwt(subject: TestSubject, authorizationDetailsRaw: adNode);

        SetupRequiredAndValidatorOk(request, jwt);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.AuthorizationDetails);
        Assert.Equal(adWire, grant.Context.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task UnsupportedSubjectTokenType_RejectsWithInvalidRequest()
    {
        var clientInfo = ClientWithAllowlist(null);
        var request = ExchangeRequest("urn:ietf:params:oauth:token-type:saml2");

        SetupRequiredOnly(request);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("saml2", error.ErrorDescription);
    }

    [Fact]
    public async Task EmptyAllowlist_RejectsEveryRequest()
    {
        var clientInfo = ClientWithAllowlist();  // empty array -> deny-all
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("not permitted", error.ErrorDescription);
    }

    [Fact]
    public async Task SubjectTokenTypeNotInAllowlist_Rejected()
    {
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.IdToken);  // only id_token allowed
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allowlist", error.ErrorDescription);
    }

    [Fact]
    public async Task ActorTokenPresent_RejectedAsNotYetSupported()
    {
        // Delegation lands in #143 slice 3. Slice 1 must reject loudly to avoid silently
        // downgrading a requested delegation to impersonation -- the resulting token
        // would not reflect the requested act chain.
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = "actor.jwt.signature",
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,
        };

        SetupRequiredOnly(request);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("Delegation", error.ErrorDescription);
    }

    [Fact]
    public async Task JwtValidationFailure_RejectsWithInvalidRequest()
    {
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        SetupRequiredOnly(request);

        _jwtValidator
            .Setup(v => v.ValidateAsync(SubjectTokenWire, ValidationOptions.Default))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "signature mismatch"));

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("invalid", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingSubClaimInJwt_Rejected()
    {
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);
        var jwtWithoutSub = TestJwt(subject: null);

        SetupRequiredAndValidatorOk(request, jwtWithoutSub);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("sub", error.ErrorDescription);
    }

    [Fact]
    public async Task ClientWithNullAllowlist_AcceptsAnyJwtBasedSubjectTokenType()
    {
        // Tri-state semantics: null allowlist = no per-client constraint.
        // The hard list of SupportedSubjectTokenTypes inside the handler still applies.
        var clientInfo = ClientWithAllowlist(null);
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken);
        var jwt = TestJwt(subject: TestSubject);

        SetupRequiredAndValidatorOk(request, jwt);

        var result = await _handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
    }

    // ──── helpers ────

    private void SetupRequiredOnly(TokenRequest request)
    {
        _parameterValidator.Setup(v => v.Required(request.SubjectToken, nameof(request.SubjectToken)));
        _parameterValidator.Setup(v => v.Required(request.SubjectTokenType, nameof(request.SubjectTokenType)));
    }

    private void SetupRequiredAndValidatorOk(TokenRequest request, JsonWebToken jwt)
    {
        SetupRequiredOnly(request);
        _jwtValidator
            .Setup(v => v.ValidateAsync(SubjectTokenWire, ValidationOptions.Default))
            .ReturnsAsync(jwt);
    }

    private static ClientInfo ClientWithAllowlist(params string[]? allowlist) =>
        new(ClientId) { TokenExchangeAllowedSubjectTokenTypes = allowlist };

    private static TokenRequest ExchangeRequest(string subjectTokenType) => new()
    {
        GrantType = GrantTypes.TokenExchange,
        SubjectToken = SubjectTokenWire,
        SubjectTokenType = subjectTokenType,
    };

    private JsonWebToken TestJwt(string? subject, JsonArray? authorizationDetailsRaw = null)
    {
        var now = _timeProvider.GetUtcNow();
        var jwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = "https://issuer.example.com",
                IssuedAt = now,
                ExpiresAt = now.AddHours(1),
            },
        };
        if (!string.IsNullOrEmpty(subject))
            jwt.Payload.Subject = subject;
        if (authorizationDetailsRaw is not null)
            jwt.Payload.Json[IanaClaimTypes.AuthorizationDetails] = authorizationDetailsRaw;
        return jwt;
    }
}
