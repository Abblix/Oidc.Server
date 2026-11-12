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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Common.Configuration;
using System.Globalization;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="PrivateKeyJwtAuthenticator"/> verifying JWT assertion authentication
/// as defined in RFC 7523 and OpenID Connect Core 1.0.
/// Tests cover JWT validation, replay attack prevention, and various error conditions.
/// </summary>
public class PrivateKeyJwtAuthenticatorTests
{
    private const string ClientId = "test_client_789";
    private const string JwtAssertion = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

    /// <summary>
    /// The issuer identifier of the tenant every request here is served at, which RFC 10070 section 4 makes
    /// the sole audience a client authentication assertion may carry; the token helpers write it by default.
    /// </summary>
    private const string IssuerIdentifier = "https://issuer.example.com";

    /// <summary>
    /// Where the transport serves the tenant's token endpoint, as its endpoint resolver answers it.
    /// </summary>
    private const string TokenEndpoint = IssuerIdentifier + "/connect/token";

    private const string PushedAuthorizationRequestEndpoint = IssuerIdentifier + "/connect/par";

    /// <summary>
    /// The instant the authenticator reads, before the expiry every assertion here carries, so no assertion is
    /// refused for its age on whatever day the suite runs.
    /// </summary>
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-01T00:00:00Z", CultureInfo.InvariantCulture);

    public PrivateKeyJwtAuthenticatorTests()
    {
        // Fixture auto-configures license
    }

    /// <summary>
    /// Verifies that valid JWT assertion with matching issuer and subject successfully authenticates the client.
    /// This is the standard flow for private_key_jwt authentication method.
    /// </summary>
    [Fact]
    public async Task ValidJwtAssertion_ShouldAuthenticate()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        // A spec-valid client assertion carries a jti (OIDC Core section 9 REQUIRED).
        var validToken = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "valid-jti-assertion",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// A JWT made for some other purpose is not proof of who the client is. RFC 8725 Section 3.11 calls this
    /// token confusion, and the sharpest case is an access token the client legitimately holds, presented as
    /// its credential. The verifiable-credential and security-event rows are the reason the refusal is not
    /// limited to what this server issues: the client signs its own assertion, so a credential or a security
    /// event it signed elsewhere is equally within reach. Everything else about the assertion below is valid - issuer,
    /// subject, jti and expiry all check out - so the type is the only thing standing between the two meanings.
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenTypes.AccessToken)]
    [InlineData(JsonWebTokenTypes.LogoutToken)]
    [InlineData(JwtTypes.RefreshToken)]
    [InlineData(JsonWebTokenTypes.VerifiableCredential)]
    [InlineData(JsonWebTokenTypes.SecurityEvent)]
    public async Task AnotherKindPresentedAsAssertion_ShouldReturnNull(string tokenType)
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "valid-jti-assertion",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        token.Header.Type = tokenType;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// The values a conformant sender may use cannot be enumerated - RFC 10070 section 4 asks for
    /// <c>client-authentication+jwt</c> "or another more specific explicit type value defined by a
    /// specification profiling this specification", and calls refusing a JWT without an explicit type NOT
    /// RECOMMENDED. So an absent, generic or unfamiliar type has to pass, or the check would refuse honest
    /// callers rather than confused tokens.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.Jwt)]
    [InlineData(JsonWebTokenTypes.ClientAuthentication)]
    [InlineData("something-a-profile-defined+jwt")]
    public async Task APermittedOrUnfamiliarType_ShouldAuthenticate(string? tokenType)
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, $"valid-jti-{tokenType ?? "none"}",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        token.Header.Type = tokenType;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ClientId, result.ClientId);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type is missing.
    /// Both client_assertion_type and client_assertion are required.
    /// </summary>
    [Fact]
    public async Task MissingClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion is missing.
    /// Both client_assertion_type and client_assertion are required.
    /// </summary>
    [Fact]
    public async Task MissingClientAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion_type is not JWT bearer.
    /// Only urn:ietf:params:oauth:client-assertion-type:jwt-bearer is supported.
    /// </summary>
    [Fact]
    public async Task WrongClientAssertionType_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = "unsupported_type",
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when JWT validation fails.
    /// Invalid JWTs (wrong signature, expired, etc.) should be rejected.
    /// </summary>
    [Fact]
    public async Task InvalidJwt_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new JwtValidationError(JwtError.InvalidToken, "Invalid signature"));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when issuer and subject claims don't match.
    /// For client authentication, iss and sub must both equal the client_id.
    /// </summary>
    [Fact]
    public async Task MismatchedIssuerAndSubject_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var invalidToken = CreateValidJwtToken("different_issuer", ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(invalidToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when issuer claim is missing from JWT.
    /// The iss claim is required for client authentication.
    /// </summary>
    [Fact]
    public async Task MissingIssuerClaim_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutIssuer = CreateValidJwtToken(null, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutIssuer, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when subject claim is missing from JWT.
    /// The sub claim is required for client authentication.
    /// </summary>
    [Fact]
    public async Task MissingSubjectClaim_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutSubject = CreateValidJwtToken(ClientId, null);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutSubject, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when the client is configured to use a different authentication method.
    /// The authenticator only accepts clients configured for private_key_jwt.
    /// </summary>
    [Fact]
    public async Task WrongAuthenticationMethod_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        clientInfo.TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost; // Wrong method

        var validToken = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the JWT ID (jti) and expiration time (exp) are recorded in the replay cache.
    /// This prevents replay attacks by ensuring tokens can only be used once.
    /// </summary>
    [Fact]
    public async Task ValidJwtWithJtiAndExp_ShouldRecordInReplayCache()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var jti = "unique_jwt_id_123";
        var expiresAt = DateTimeOffset.Parse(
            "2027-01-01T00:05:00Z", System.Globalization.CultureInfo.InvariantCulture);

        var validToken = CreateValidJwtTokenWithJtiAndExp(ClientId, ClientId, jti, expiresAt);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.NotNull(result);
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(
                It.Is<string>(id => id == jti),
                It.Is<DateTimeOffset>(exp =>
                    Math.Abs((exp - expiresAt).TotalSeconds) < 1)),
            Times.Once);
    }

    /// <summary>
    /// Verifies that a replayed assertion is rejected: the replay cache reports the jti as
    /// already present, and the single TryReserveAsync call makes the reserve-and-check atomic -
    /// two concurrent presenters of the same assertion cannot both pass.
    /// </summary>
    [Fact]
    public async Task ReplayedAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var validToken = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "replayed-jti",
            DateTimeOffset.Parse("2027-01-01T00:05:00Z", System.Globalization.CultureInfo.InvariantCulture));

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(validToken, clientInfo));

        mocks.ReplayCache
            .Setup(r => r.TryReserveAsync("replayed-jti", It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(false);

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that an assertion without a jti claim is rejected. OpenID Connect Core section 9 makes
    /// jti REQUIRED ("A unique identifier for the token, which can be used to prevent reuse of the
    /// token"); accepting a jti-less assertion would leave it replayable within its expiry window,
    /// since single-use enforcement keys off jti.
    /// </summary>
    [Fact]
    public async Task AssertionWithoutJti_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutJti = CreateValidJwtToken(ClientId, ClientId);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutJti, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
        // A rejected assertion is never recorded in the replay cache.
        mocks.ReplayCache.Verify(
            r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// Verifies that an assertion without an exp claim is rejected. RFC 7523 section 3 makes exp REQUIRED
    /// ("The JWT MUST contain an 'exp' (expiration time) claim that limits the time window during
    /// which the JWT can be used"); without it the replay-registry entry has no TTL to key off,
    /// so the assertion would be replayable indefinitely.
    /// </summary>
    [Fact]
    public async Task AssertionWithoutExp_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, mocks) = CreateAuthenticator();

        var clientInfo = CreateClientInfo(ClientId);
        var tokenWithoutExp = CreateValidJwtTokenWithJti(ClientId, ClientId, "jti-without-exp");

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(tokenWithoutExp, clientInfo));

        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that authentication fails when client_assertion is empty string.
    /// </summary>
    [Fact]
    public async Task EmptyClientAssertion_ShouldReturnNull()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();
        var request = new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = string.Empty
        };

        // Act
        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), request);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that the authenticator reports the correct supported authentication method.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldReturnPrivateKeyJwt()
    {
        // Arrange
        var (authenticator, _) = CreateAuthenticator();

        // Act
        var methods = authenticator.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Single(methods);
        Assert.Equal(ClientAuthenticationMethods.PrivateKeyJwt, methods[0]);
    }


    /// <summary>
    /// RFC 10070 section 4, case B: the authorization server "MUST reject any JWT that does not contain its
    /// issuer identifier as its sole audience value", and "the token endpoint URL of the authorization server
    /// MUST NOT be used as an audience value". The rule is the specification's own, so it holds whatever
    /// profile governs the client. An issuer named beside another recipient is refused too, or an assertion
    /// minted for that recipient could be replayed here.
    /// </summary>
    [Theory]
    [MemberData(nameof(AudiencesOtherThanTheIssuerAlone))]
    public async Task AssertionAudienceIsNotTheIssuerAlone_ShouldReturnNull(
        ClientSecurityProfile profile, string[] audiences)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-not-the-issuer-alone",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Audiences = audiences;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Null(result);
        AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// Each audience RFC 10070 section 4 refuses, under no profile and under FAPI 2.0.
    /// </summary>
    public static TheoryData<ClientSecurityProfile, string[]> AudiencesOtherThanTheIssuerAlone()
    {
        var data = new TheoryData<ClientSecurityProfile, string[]>();
        foreach (var profile in new[] { ClientSecurityProfile.None, ClientSecurityProfile.Fapi2 })
        {
            data.Add(profile, [IssuerIdentifier + "/connect/token"]);
            data.Add(profile, ["https://another-issuer.example.com"]);
            data.Add(profile, [IssuerIdentifier, "https://another.example.com"]);
            data.Add(profile, [IssuerIdentifier + "/"]);
        }

        return data;
    }

    /// <summary>
    /// A member that is not a string still counts as an audience value, so the issuer beside one is not the
    /// sole value RFC 10070 section 4 requires, whatever the profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public async Task AssertionAudienceWithAMemberThatIsNotAString_ShouldReturnNull(ClientSecurityProfile profile)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-with-a-number",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = new JsonArray(IssuerIdentifier, 42);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Null(result);
        AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// RFC 10070 section 4 admits the issuer as the one member of an array, while FAPI 2.0 section 5.3.2.1 has a
    /// server held to the profile "only accept its issuer identifier value (as defined in [RFC8414]) as a string in
    /// the aud claim received in client authentication assertions". The profile governing the client is the
    /// tenant's default tightened by the client's own, so a client registered under FAPI 2.0 is held to it at a
    /// tenant without a profile, and one naming None cannot step below the tenant's.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, null, true)]
    [InlineData(ClientSecurityProfile.Fapi2, null, false)]
    [InlineData(ClientSecurityProfile.None, ClientSecurityProfile.Fapi2, false)]
    [InlineData(ClientSecurityProfile.Fapi2, ClientSecurityProfile.None, false)]
    public async Task AssertionAudienceAsAnArrayOfTheIssuer_IsAcceptedOutsideFapi2Only(
        ClientSecurityProfile profile, ClientSecurityProfile? clientProfile, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        clientInfo.SecurityProfile = clientProfile;
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-as-an-array",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = new JsonArray(IssuerIdentifier);

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Equal(accepted, result is not null);
        if (!accepted)
            AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// The issuer alone, as a string, is accepted under every profile, which keeps the refusals in
    /// <see cref="AssertionAudienceIsNotTheIssuerAlone_ShouldReturnNull"/> from being a check that refuses
    /// every assertion.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public async Task AssertionAudienceIsTheIssuerAlone_ShouldAuthenticate(ClientSecurityProfile profile)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "audience-is-the-issuer",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.NotNull(result);
    }

    /// <summary>
    /// A client the host still lets use the token endpoint URL, as OpenID Connect Core 1.0 section 9 recommended
    /// before RFC 10070, is accepted with that URL alone and as a string, the form such a client writes. The
    /// exception reaches no further: the URL in an array or beside the issuer, and the pushed authorization request
    /// endpoint URL, are still refused, and so is the token endpoint URL for a client without the exception.
    /// </summary>
    [Theory]
    [MemberData(nameof(AudiencesUnderTheTokenEndpointException))]
    public async Task TokenEndpointAudience_IsAcceptedOnlyAloneAndOnlyForAClientAllowedIt(
        bool allowed, JsonNode audience, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = CreateClientInfo(ClientId);
        clientInfo.AcceptTokenEndpointAsClientAssertionAudience = allowed;
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "token-endpoint-audience",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = audience.DeepClone();

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Equal(accepted, result is not null);
        if (!accepted)
            AssertRefusedForItsAudience(mocks);
    }

    public static TheoryData<bool, JsonNode, bool> AudiencesUnderTheTokenEndpointException() => new()
    {
        { true, JsonValue.Create(TokenEndpoint), true },
        { true, JsonValue.Create(IssuerIdentifier), true },
        { true, new JsonArray(TokenEndpoint), false },
        { true, new JsonArray(IssuerIdentifier, TokenEndpoint), false },
        { true, JsonValue.Create(PushedAuthorizationRequestEndpoint), false },
        { false, JsonValue.Create(TokenEndpoint), false },
    };

    /// <summary>
    /// The URL a flagged client may name is the tenant's token endpoint on the issuer's own host, whatever host the
    /// request names. A caller sending an assertion minted for another server under the same path, with that server's
    /// host in the request, is refused; the same path on the issuer's host is accepted, as discovery advertises it.
    /// </summary>
    [Theory]
    [InlineData("https://other-as.example/connect/token", false)]
    [InlineData(TokenEndpoint, true)]
    public async Task TokenEndpointAudience_IsTheIssuersHostNotTheRequests(string audience, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator(new Uri("https://other-as.example/connect/token"));
        var result = await AuthenticateFlaggedClient(authenticator, mocks, ClientSecurityProfile.None, audience);

        Assert.Equal(accepted, result is not null);
        if (!accepted)
            AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// For an issuer written with its default port and an upper-case host, the token endpoint is accepted both as
    /// discovery advertises it, on the normalized authority, and on the authority as the issuer writes it; each is
    /// compared as written, so a third spelling of the same host, and another host, are refused.
    /// </summary>
    [Theory]
    [InlineData("https://issuer.example.com/connect/token", true)]
    [InlineData("https://ISSUER.example.com:443/connect/token", true)]
    [InlineData("https://issuer.example.com:443/connect/token", false)]
    [InlineData("https://other-as.example/connect/token", false)]
    public async Task TokenEndpointAudience_IsAcceptedOnTheIssuersAuthorityEitherWayItIsWritten(string audience, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            AcceptTokenEndpointAsClientAssertionAudience = true,
        };
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "normalized-authority",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = audience;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var tenant = new TestIssuer { Issuer = new Uri("https://ISSUER.example.com:443") }.ToTenant();
        var result = await authenticator.TryAuthenticateClientAsync(tenant, new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Equal(accepted, result is not null);
        if (!accepted)
            AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// A tenant served under a path carries that path in the resolved endpoint already, so the spelling on the issuer's
    /// authority as written takes the authority alone: the tenant's path appears once, and a spelling repeating it is
    /// refused.
    /// </summary>
    [Theory]
    [InlineData("https://ISSUER.example.com:443/tenants/acme/connect/token", true)]
    [InlineData("https://issuer.example.com/tenants/acme/connect/token", true)]
    [InlineData("https://ISSUER.example.com:443/tenants/acme/tenants/acme/connect/token", false)]
    public async Task TokenEndpointAudience_ForATenantUnderAPath_NamesThePathOnce(string audience, bool accepted)
    {
        var (authenticator, mocks) = CreateAuthenticator(new Uri("https://issuer.example.com/tenants/acme/connect/token"));
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            AcceptTokenEndpointAsClientAssertionAudience = true,
        };
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "tenant-under-a-path",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = audience;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        var tenant = new TestIssuer { Issuer = new Uri("https://ISSUER.example.com:443/tenants/acme") }.ToTenant();
        var result = await authenticator.TryAuthenticateClientAsync(tenant, new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });

        Assert.Equal(accepted, result is not null);
        if (!accepted)
            AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// The exception does not reach a client held to FAPI 2.0, whose section 5.3.2.1 accepts the issuer identifier
    /// alone: the audience link refuses it itself, before its jti is spent, whatever runs after it.
    /// </summary>
    [Fact]
    public async Task TokenEndpointAudience_IsRefusedUnderFapi2EvenForAFlaggedClient()
    {
        var (authenticator, mocks) = CreateAuthenticator();
        var result = await AuthenticateFlaggedClient(authenticator, mocks, ClientSecurityProfile.Fapi2, TokenEndpoint);

        Assert.Null(result);
        AssertRefusedForItsAudience(mocks);
        mocks.ReplayCache.Verify(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()), Times.Never);
    }

    /// <summary>
    /// Where nothing resolves the token endpoint - a host running the core without a transport, or an endpoint that is
    /// not mapped - a flagged client's token endpoint audience matches nothing and is refused, without an exception.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TokenEndpointAudience_IsRefusedWhereNothingResolvesTheEndpoint(bool resolverRegistered)
    {
        var (authenticator, mocks) = CreateAuthenticator(tokenEndpoint: null, resolverRegistered);
        var result = await AuthenticateFlaggedClient(authenticator, mocks, ClientSecurityProfile.None, TokenEndpoint);

        Assert.Null(result);
        AssertRefusedForItsAudience(mocks);
    }

    /// <summary>
    /// A client allowed the token endpoint URL, authenticating with an assertion whose audience is
    /// <paramref name="audience"/> at a tenant held to <paramref name="profile"/>.
    /// </summary>
    private async Task<ClientInfo?> AuthenticateFlaggedClient(
        PrivateKeyJwtAuthenticator authenticator, Mocks mocks, ClientSecurityProfile profile, string audience)
    {
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            AcceptTokenEndpointAsClientAssertionAudience = true,
        };
        var token = CreateValidJwtTokenWithJtiAndExp(
            ClientId, ClientId, "flagged-client",
            DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture));
        token.Payload.Json[JwtClaimTypes.Audience] = audience;

        mocks.ClientJwtValidator
            .Setup(v => v.ValidateAsync(TestTenant.Matched, JwtAssertion, It.IsAny<TokenTypePolicy>(), It.IsAny<ValidationOptions>()))
            .ReturnsAsync(new ValidJsonWebToken(token, clientInfo));

        return await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest
        {
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            ClientAssertion = JwtAssertion,
        });
    }

    /// <summary>
    /// Asserts the refusal came from the audience link rather than from a check that runs before it, so a row
    /// cannot stay green on a refusal it was not written for.
    /// </summary>
    private static void AssertRefusedForItsAudience(Mocks mocks)
        => mocks.Logger.Verify(
            l => l.Log(
                LogLevel.Warning,
                It.Is<EventId>(e => e.Id == LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.AudienceIsNotTheIssuerAlone),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);

    /// <summary>
    /// The tenant a request is served at, holding its clients to <paramref name="profile"/> by default.
    /// </summary>
    private static TenantDefinition TenantAt(ClientSecurityProfile profile)
        => new TestIssuer { Issuer = new Uri(IssuerIdentifier), DefaultSecurityProfile = profile }.ToTenant();

    /// <summary>
    /// Creates a new instance of PrivateKeyJwtAuthenticator with mocked dependencies for testing.
    /// </summary>
    /// <returns>A tuple containing the authenticator instance and the mock objects.</returns>
    private (PrivateKeyJwtAuthenticator authenticator, Mocks mocks) CreateAuthenticator()
        => CreateAuthenticator(new Uri(TokenEndpoint));

    /// <summary>
    /// The authenticator over a transport whose resolver answers <paramref name="tokenEndpoint"/> for the token
    /// endpoint, or over a host with no resolver registered at all.
    /// </summary>
    private (PrivateKeyJwtAuthenticator authenticator, Mocks mocks) CreateAuthenticator(
        Uri? tokenEndpoint, bool resolverRegistered = true)
    {
        var logger = new Mock<ILogger<PrivateKeyJwtAuthenticator>>();
        logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
        var replayCache = new Mock<IReplayCache>(MockBehavior.Strict);
        var clientJwtValidator = new Mock<IClientJwtValidator>(MockBehavior.Strict);

        // Setup default behavior for the replay cache: every jti is fresh
        replayCache
            .Setup(r => r.TryReserveAsync(It.IsAny<string>(), It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(true);

        // Create service provider with scoped services
        var endpointResolver = new Mock<IOidcEndpointResolver>();
        endpointResolver.Setup(r => r.Resolve(OidcEndpoints.Token)).Returns(tokenEndpoint);
        endpointResolver.Setup(r => r.Resolve(OidcEndpoints.PushedAuthorizationRequest))
            .Returns(new Uri(PushedAuthorizationRequestEndpoint));

        var services = new ServiceCollection();
        services.AddScoped<IClientJwtValidator>(_ => clientJwtValidator.Object);
        if (resolverRegistered)
            services.AddScoped<IOidcEndpointResolver>(_ => endpointResolver.Object);
        var serviceProvider = services.BuildServiceProvider(validateScopes: true);

        var authenticator = new PrivateKeyJwtAuthenticator(
            logger.Object,
            replayCache.Object,
            serviceProvider,
            new FakeTimeProvider(Now));

        var mocks = new Mocks
        {
            Logger = logger,
            ReplayCache = replayCache,
            ClientJwtValidator = clientJwtValidator,
        };

        return (authenticator, mocks);
    }

    /// <summary>
    /// Creates a test ClientInfo object configured for private_key_jwt authentication.
    /// </summary>
    /// <param name="clientId">The client ID.</param>
    /// <returns>A configured ClientInfo object.</returns>
    private ClientInfo CreateClientInfo(string clientId)
    {
        return new ClientInfo(clientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt
        };
    }

    /// <summary>
    /// Creates a valid JWT token with specified issuer and subject.
    /// Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss), or null to omit.</param>
    /// <param name="subject">The subject claim (sub), or null to omit.</param>
    /// <returns>A JsonWebToken with the specified claims.</returns>
    private JsonWebToken CreateValidJwtToken(string? issuer, string? subject)
    {
        var payloadJson = new JsonObject { [JwtClaimTypes.Audience] = IssuerIdentifier };
        if (issuer != null)
            payloadJson[JwtClaimTypes.Issuer] = issuer;
        if (subject != null)
            payloadJson[JwtClaimTypes.Subject] = subject;

        var headerJson = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = "RS256",
            [JwtClaimTypes.Type] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }

    /// <summary>
    /// Creates a JWT token with a jti claim but no exp claim, for testing the RFC 7523 section 3
    /// expiration requirement. Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss).</param>
    /// <param name="subject">The subject claim (sub).</param>
    /// <param name="jwtId">The JWT ID claim (jti).</param>
    /// <returns>A JsonWebToken with the specified claims and no expiration.</returns>
    private JsonWebToken CreateValidJwtTokenWithJti(string issuer, string subject, string jwtId)
    {
        var payloadJson = new JsonObject
        {
            [JwtClaimTypes.Issuer] = issuer,
            [JwtClaimTypes.Subject] = subject,
            [JwtClaimTypes.JwtId] = jwtId
        };

        var headerJson = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = "RS256",
            [JwtClaimTypes.Type] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }

    /// <summary>
    /// Creates a valid JWT token with jti and exp claims for testing token registry.
    /// Uses real JsonObject instances for JWT payload - NOT mocked!
    /// </summary>
    /// <param name="issuer">The issuer claim (iss).</param>
    /// <param name="subject">The subject claim (sub).</param>
    /// <param name="jwtId">The JWT ID claim (jti).</param>
    /// <param name="expiresAt">The expiration time (exp).</param>
    /// <returns>A JsonWebToken with the specified claims.</returns>
    private JsonWebToken CreateValidJwtTokenWithJtiAndExp(
        string issuer,
        string subject,
        string jwtId,
        DateTimeOffset expiresAt)
    {
        var payloadJson = new JsonObject
        {
            [JwtClaimTypes.Issuer] = issuer,
            [JwtClaimTypes.Subject] = subject,
            [JwtClaimTypes.Audience] = IssuerIdentifier,
            [JwtClaimTypes.JwtId] = jwtId,
            [JwtClaimTypes.ExpiresAt] = expiresAt.ToUnixTimeSeconds()
        };

        var headerJson = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = "RS256",
            [JwtClaimTypes.Type] = "JWT"
        };

        return new JsonWebToken
        {
            Header = new JsonWebTokenHeader(headerJson),
            Payload = new JsonWebTokenPayload(payloadJson)
        };
    }

    /// <summary>
    /// Container class for holding all mock objects used in tests.
    /// </summary>
    private sealed class Mocks
    {
        public Mock<ILogger<PrivateKeyJwtAuthenticator>> Logger { get; init; } = null!;
        public Mock<IReplayCache> ReplayCache { get; init; } = null!;
        public Mock<IClientJwtValidator> ClientJwtValidator { get; init; } = null!;
    }
}
