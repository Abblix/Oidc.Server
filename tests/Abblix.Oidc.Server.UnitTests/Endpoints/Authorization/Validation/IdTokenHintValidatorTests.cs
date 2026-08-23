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
/// The half of <c>id_token_hint</c> handling that decides whether a hint may be believed at all.
/// </summary>
/// <remarks>
/// The filter that consumes the result is covered in <c>AuthorizationRequestProcessorTests</c>, which sets
/// the subject on the context directly. These are what say a hint on the wire ever becomes that subject, and
/// what a hint has to survive first.
/// </remarks>
public class IdTokenHintValidatorTests
{
    private const string Hint = "hint.jwt";
    private const string Subject = "user_42";

    private static readonly DateTimeOffset Expiry = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IAuthServiceJwtValidator> _jwtValidator = new(MockBehavior.Strict);
    private readonly IdTokenHintValidator _validator;

    public IdTokenHintValidatorTests()
    {
        _validator = new IdTokenHintValidator(_jwtValidator.Object);
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

    private void SetupHint(JsonWebToken token)
    {
        Result<JsonWebToken, JwtValidationError> success = token;
        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(success);
    }

    private static JsonWebToken IdToken(
        string? subject = Subject,
        string? audience = TestConstants.DefaultClientId,
        DateTimeOffset? expiresAt = null,
        string? type = null)
    {
        var token = new JsonWebToken
        {
            Payload =
            {
                Subject = subject,
                ExpiresAt = expiresAt ?? Expiry,
            }
        };

        if (audience is not null)
            token.Payload.Audiences = [audience];

        if (type is not null)
            token.Header.Type = type;

        return token;
    }

    /// <summary>
    /// An ordinary hint records the end user it names, which is the whole output of this validator.
    /// </summary>
    [Fact]
    public async Task AnIdTokenForThisClient_RecordsItsSubject()
    {
        var context = Context();
        SetupHint(IdToken());

        Assert.Null(await _validator.ValidateAsync(context));
        Assert.Equal(Subject, context.IdTokenHintSubject);
    }

    /// <summary>
    /// A request without a hint records nothing and asks the validator nothing.
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
    /// A hint the shared validator refuses - a bad signature, an unknown issuer - is an invalid request.
    /// </summary>
    [Fact]
    public async Task AHintThatDoesNotValidate_IsRefused()
    {
        var context = Context();
        Result<JsonWebToken, JwtValidationError> failure =
            new JwtValidationError(JwtError.InvalidToken, "bad signature");

        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .ReturnsAsync(failure);

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Null(context.IdTokenHintSubject);
    }

    /// <summary>
    /// A hint addressed to another client is refused, whether or not it names a real end user.
    /// </summary>
    /// <remarks>
    /// This is the check that stops one client naming another client's session, and it is why the audience
    /// is not validated by the shared validator: OpenID Connect Core 1.0 Section 3.1.2.1 says this server
    /// "need not be listed as an audience of the ID Token when it is used as an id_token_hint value", so
    /// the audience that matters is the requesting client's, tested here.
    /// </remarks>
    [Fact]
    public async Task AHintIssuedForAnotherClient_IsRefused()
    {
        var context = Context();
        SetupHint(IdToken(audience: "another-client"));

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// Another own-issued token of this server, addressed to this client, is refused by its type.
    /// </summary>
    /// <remarks>
    /// RFC 8725 Section 3.12 on keeping the validation rules of different kinds of JWT mutually exclusive:
    /// signature and audience both pass for these, so the type is what parts them from an ID token.
    /// </remarks>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JsonWebTokenTypes.RequestObject)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    public async Task AnotherKindOfOwnIssuedToken_IsRefused(string type)
    {
        var context = Context();
        SetupHint(IdToken(type: type));

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// A token carrying no subject is refused, which is what stops a JARM response JWT.
    /// </summary>
    /// <remarks>
    /// That one is untyped, carries this client's audience and an expiry, so it clears every check above.
    /// The subject is the only thing it does not have.
    /// </remarks>
    [Fact]
    public async Task ATokenWithNoSubject_IsRefused()
    {
        var context = Context();
        SetupHint(IdToken(subject: null));

        var error = await _validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// The options handed to the shared validator switch off the lifetime and the audience, and require an
    /// expiration time to be present.
    /// </summary>
    /// <remarks>
    /// Asserted rather than left to the three behaviours it produces, because two of them cannot be
    /// observed from here at all: whether an expired hint is accepted and whether an audience naming
    /// somebody else is tolerated are decided inside the validator this test mocks. What this pins is the
    /// instruction given to it.
    /// </remarks>
    [Fact]
    public async Task TheHintIsValidatedWithoutItsLifetimeOrAudienceAndWithARequiredExpiry()
    {
        var context = Context();
        ValidationOptions? asked = null;

        Result<JsonWebToken, JwtValidationError> success = IdToken();
        _jwtValidator
            .Setup(v => v.ValidateAsync(Hint, It.IsAny<ValidationOptions>()))
            .Callback((string _, ValidationOptions options) => asked = options)
            .ReturnsAsync(success);

        await _validator.ValidateAsync(context);

        Assert.NotNull(asked);
        Assert.False(asked.Value.HasFlag(ValidationOptions.ValidateLifetime));
        Assert.False(asked.Value.HasFlag(ValidationOptions.ValidateAudience));
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireExpirationTime));

        // And the checks that do not depend on the lifetime are still asked for.
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidIssuer));
        Assert.True(asked.Value.HasFlag(ValidationOptions.RequireValidSignedTokens));
    }
}
