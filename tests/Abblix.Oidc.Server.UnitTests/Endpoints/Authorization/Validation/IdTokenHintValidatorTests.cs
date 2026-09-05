// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// What the authorization endpoint does with a hint once it is known to be an ID token this server issued.
/// </summary>
/// <remarks>
/// Whether it is one at all is <see cref="IIdTokenHintParser"/>'s question, covered in
/// <c>IdTokenHintParserTests</c> and mocked here. What is left is the part specific to this endpoint: the
/// audience must name the requesting client, and the subject it records is what the session filter compares
/// against.
/// </remarks>
public class IdTokenHintValidatorTests
{
    private const string Hint = "hint.jwt";
    private const string Subject = "user_42";

    private readonly Mock<IIdTokenHintParser> _hintParser = new(MockBehavior.Strict);
    private readonly IdTokenHintValidator _validator;

    public IdTokenHintValidatorTests()
    {
        _validator = new IdTokenHintValidator(_hintParser.Object);
    }

    private static AuthorizationValidationContext Context(string? hint = Hint) => new(
        new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
            IdTokenHint = hint,
        })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        ResponseMode = ResponseModes.Query,
    };

    private void SetupParsed(string? subject = Subject, string? audience = TestConstants.DefaultClientId)
    {
        var token = new JsonWebToken { Payload = { Subject = subject } };
        if (audience is not null)
            token.Payload.Audiences = [audience];

        Result<JsonWebToken, string> parsed = token;
        _hintParser.Setup(p => p.ParseAsync(Hint)).ReturnsAsync(parsed);
    }

    /// <summary>
    /// An ordinary hint records the end user it names, which is the whole output of this validator.
    /// </summary>
    [Fact]
    public async Task AnIdTokenForThisClient_RecordsItsSubject()
    {
        var context = Context();
        SetupParsed();

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Equal(Subject, context.IdTokenHintSubject);
    }

    /// <summary>
    /// A request without a hint records nothing and asks the parser nothing.
    /// </summary>
    /// <remarks>
    /// Verified on a strict mock with no setup, so a validator that consulted it anyway would throw rather
    /// than quietly pass.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ARequestWithoutAHint_RecordsNothing(string? hint)
    {
        var context = Context(hint);

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Null(context.IdTokenHintSubject);
    }

    /// <summary>
    /// A hint the parser refuses is an invalid request, and the reason it gave is what the client is told.
    /// </summary>
    [Fact]
    public async Task AHintTheParserRefuses_IsAnInvalidRequest()
    {
        var context = Context();
        Result<JsonWebToken, string> refused = "The id token hint is not an ID Token";
        _hintParser.Setup(p => p.ParseAsync(Hint)).ReturnsAsync(refused);

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("The id token hint is not an ID Token", error.ErrorDescription);
        Assert.Null(context.IdTokenHintSubject);
    }

    /// <summary>
    /// A hint addressed to another client is refused, whether or not it names a real end user.
    /// </summary>
    /// <remarks>
    /// This is the check that stops one client naming another client's session, and it is why the parser
    /// leaves the audience alone: OpenID Connect Core 1.0 Section 3.1.2.1 says this server "need not be
    /// listed as an audience of the ID Token when it is used as an id_token_hint value", so the audience
    /// that matters is the requesting client's, tested here.
    /// </remarks>
    [Theory]
    [InlineData("another-client")]
    [InlineData(null)]
    public async Task AHintNotAddressedToThisClient_IsRefused(string? audience)
    {
        var context = Context();
        SetupParsed(audience: audience);

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Null(context.IdTokenHintSubject);
    }

    /// <summary>
    /// A token carrying no subject is refused, which is what stops a JARM response JWT.
    /// </summary>
    /// <remarks>
    /// That one is untyped, carries this client's audience and an expiry, so it clears the parser and the
    /// audience check alike. The subject is the only thing it does not have.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ATokenWithNoSubject_IsRefused(string? subject)
    {
        var context = Context();
        SetupParsed(subject: subject);

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Null(context.IdTokenHintSubject);
    }
}
