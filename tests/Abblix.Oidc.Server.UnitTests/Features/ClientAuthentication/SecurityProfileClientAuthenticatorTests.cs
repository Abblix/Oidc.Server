// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Jwt;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The profile has to reach a client the configuration paths never see: one registered dynamically
/// while no profile was in force, which lives in the store and is re-read by nobody when the
/// deployment turns a profile on.
/// </summary>
public class SecurityProfileClientAuthenticatorTests
{
    private const string ClientId = "stored-client";

    /// <summary>
    /// The tenant a request is served at, holding its clients to <paramref name="defaultProfile"/> by default.
    /// </summary>
    private static TenantDefinition TenantAt(ClientSecurityProfile defaultProfile)
        => new TestIssuer { DefaultSecurityProfile = defaultProfile }.ToTenant();

    private static (SecurityProfileClientAuthenticator Authenticator, Mock<IClientAuthenticator> Inner)
        CreateAuthenticator()
        => CreateAuthenticator(NullLogger<SecurityProfileClientAuthenticator>.Instance);

    private static (SecurityProfileClientAuthenticator Authenticator, Mock<IClientAuthenticator> Inner)
        CreateAuthenticator(ILogger<SecurityProfileClientAuthenticator> logger)
        => CreateAuthenticator(logger, SigningAlgorithms.PS256, []);

    /// <summary>
    /// The decorator over a client the inner authenticator returns, with the deployment's service tokens signed with
    /// <paramref name="serviceTokenAlgorithm"/> and the client publishing <paramref name="encryptionKeys"/>. Service
    /// tokens default to PS256, which every profile admits, so a refusal elsewhere is the client's own.
    /// </summary>
    private static (SecurityProfileClientAuthenticator Authenticator, Mock<IClientAuthenticator> Inner)
        CreateAuthenticator(
            ILogger<SecurityProfileClientAuthenticator> logger,
            string serviceTokenAlgorithm,
            JsonWebKey[] encryptionKeys)
    {
        var inner = new Mock<IClientAuthenticator>();
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Signing.Algorithm = serviceTokenAlgorithm;
        options.ServiceTokens.RefreshToken.Signing.Algorithm = serviceTokenAlgorithm;
        var keys = new Mock<IClientKeysProvider>();
        keys.Setup(k => k.GetEncryptionKeys(It.IsAny<ClientInfo>())).Returns(encryptionKeys.ToAsyncEnumerable());
        var authenticator = new SecurityProfileClientAuthenticator(
            inner.Object,
            logger,
            keys.Object,
            Options.Create(options));

        return (authenticator, inner);
    }

    /// <summary>
    /// FAPI 2.0 section 5.4.1 "when creating or processing JWTs": the access and refresh tokens a client is issued are
    /// signed with what the deployment configures, so a client held to FAPI 2.0 at a tenant held to none does not
    /// authenticate while they are signed RS256, before anything is spent for it.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    public async Task TheServiceTokensAClientWouldBeIssued_AreJudgedByItsProfile(string algorithm, bool authenticated)
    {
        var (authenticator, inner) = CreateAuthenticator(
            NullLogger<SecurityProfileClientAuthenticator>.Instance, algorithm, []);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            SecurityProfile = ClientSecurityProfile.Fapi2,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        });

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        Assert.Equal(authenticated, result is not null);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6.1: "For JWE, both clients and authorization servers shall not use the RSA1_5
    /// algorithm". A client publishing only RSA1_5 encryption keys has nothing left to be encrypted to, and does not
    /// authenticate; one also publishing an RSA-OAEP-256 key does.
    /// </summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task AKeySetLeavingNothingToEncryptTo_DoesNotAuthenticate(bool withOaep, bool authenticated)
    {
        JsonWebKey[] keys = withOaep
            ?
            [
                new RsaJsonWebKey { Algorithm = EncryptionAlgorithms.KeyManagement.Rsa1_5 },
                new RsaJsonWebKey { Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 },
            ]
            : [new RsaJsonWebKey { Algorithm = EncryptionAlgorithms.KeyManagement.Rsa1_5 }];
        var (authenticator, inner) = CreateAuthenticator(
            NullLogger<SecurityProfileClientAuthenticator>.Instance, SigningAlgorithms.PS256, keys);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            TlsClientCertificateBoundAccessTokens = true,
        });

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.Fapi1Advanced), new ClientRequest());

        Assert.Equal(authenticated, result is not null);
    }

    /// <summary>
    /// The value that cannot be interpreted is said out loud here, because this is the only place a
    /// client out of a host-written store is met by name. Without it the operator sees only the
    /// consequence - refusals citing requirements no configuration of theirs sets.
    /// </summary>
    [Fact]
    public async Task StoredClientWithAnUndefinedProfile_ShouldBeNamedInTheLog()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = (ClientSecurityProfile)7,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        // Selected by EVENT, not by level: this class emits a second warning of its own, and a
        // fixture that also tripped it would satisfy both assertions off the wrong line.
        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .ProfileIsNotOneThisServerDefines);

        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("7", entry.Message);
        Assert.Contains(ClientId, entry.Message);
    }

    /// <summary>
    /// The refusal an operator reads names BOTH sides, because the controls come from the two
    /// together and neither alone says where the requirement came from. A client naming the empty
    /// profile satisfies it and is refused anyway, which is the line that would otherwise send the
    /// operator looking at the client's registration for a demand the deployment made.
    /// </summary>
    [Fact]
    public async Task TheRefusal_NamesTheClientsChoiceAndTheDeploymentsFloor()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyProfile);

        Assert.Contains($"it names {ClientSecurityProfile.None}", entry.Message);
        Assert.Contains($"every client to {ClientSecurityProfile.Fapi2}", entry.Message);
    }

    /// <summary>
    /// And a client naming NO profile - which is most of them - still produces a sentence, rather
    /// than one with a hole where the name would be. This is the shape the message is read on most
    /// often, so a placeholder that renders empty for it makes the line worse than saying nothing.
    /// </summary>
    [Fact]
    public async Task TheRefusal_ReadsAsASentenceWhenTheClientNamesNoProfile()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyDeploymentProfile);

        Assert.Contains("it names no profile of its own", entry.Message);
        Assert.Contains($"every client to {ClientSecurityProfile.Fapi2}", entry.Message);
    }

    /// <summary>
    /// The structured field carries the VALUE, not the word: a consumer filtering on the profile a
    /// client named gets an enum it can compare, rather than a rendering of one.
    /// </summary>
    [Fact]
    public async Task TheRefusal_CarriesTheClientsProfileAsAValue()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyProfile);

        Assert.Equal(
            ClientSecurityProfile.None,
            Assert.IsType<ClientSecurityProfile>(
                Assert.Single(entry.Fields, f => f.Key == "ClientProfile").Value));
    }

    /// <summary>
    /// And the case where the client named nothing carries no such field at all, under an event id
    /// of its own. That id is what a consumer selects on: a filter naming an id that is PRESENT
    /// cannot be satisfied by a field dropped somewhere in the pipeline, which is what asking for an
    /// absent key would be.
    /// </summary>
    [Fact]
    public async Task TheRefusal_ForAClientNamingNothing_CarriesNoProfileFieldAndItsOwnEventId()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyDeploymentProfile);

        Assert.DoesNotContain(entry.Fields, f => f.Key == "ClientProfile");
        Assert.Equal(
            ClientSecurityProfile.Fapi2,
            Assert.IsType<ClientSecurityProfile>(
                Assert.Single(entry.Fields, f => f.Key == "DeploymentProfile").Value));
    }

    /// <summary>
    /// And a profile this server does define says nothing, or the line would be noise on every
    /// request rather than a signal about one client.
    /// </summary>
    [Fact]
    public async Task StoredClientWithADefinedProfile_ShouldNotBeNamedInTheLog()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = ClientSecurityProfile.Fapi2,
        });

        await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        Assert.DoesNotContain(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .ProfileIsNotOneThisServerDefines);
    }

    /// <summary>
    /// A client allowed the token endpoint URL as its assertion's audience authenticates at a tenant naming no
    /// profile and is refused under FAPI 2.0, whose section 5.3.2.1 accepts the issuer identifier alone, whichever
    /// way it was stored.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, true)]
    [InlineData(ClientSecurityProfile.Fapi2, false)]
    public async Task TokenEndpointAudienceException_IsRefusedUnderFapi2(ClientSecurityProfile profile, bool accepted)
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            ClientAssertionAudiences = ClientAssertionAudiences.Issuer | ClientAssertionAudiences.TokenEndpoint,
        });

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(profile), new ClientRequest());

        Assert.Equal(accepted, result is not null);
    }

    private static void Authenticates(Mock<IClientAuthenticator> inner, ClientInfo clientInfo)
        => inner.Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

    /// <summary>
    /// The scenario the decorator exists for: the shared secret was acceptable when the client
    /// registered, and the profile turned on afterwards. The credential verifies, and the client is
    /// still refused, because the registration behind it cannot satisfy the profile.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost)]
    [InlineData(ClientAuthenticationMethods.None)]
    public async Task StoredClientCannotSatisfyProfile_ShouldReturnNull(string method)
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId) { TokenEndpointAuthMethod = method });

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        Assert.Null(result);
    }

    /// <summary>
    /// The decorator runs the whole checker, not the half about credentials: a registration allowing
    /// a response type the profile forbids is refused here too, even though its credential is one the
    /// profile admits. Without this row the response-type clauses decide no outcome in this file, and
    /// a decorator reading only the authentication method would leave it green.
    /// </summary>
    [Fact]
    public async Task StoredClientAllowsAForbiddenResponseType_ShouldReturnNull()
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            // The code response type is allowed as well, so this trips the clause about a
            // FORBIDDEN response type and no other: an array carrying only the hybrid pair would
            // also trip the clause requiring the code type, and the row would stay green if the
            // clause its name points at were deleted.
            AllowedResponseTypes = [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
        });

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        Assert.Null(result);
    }

    /// <summary>
    /// A store the HOST writes can hand back a profile value the enum does not define, and no
    /// startup check can reach a host's store. Such a value resolves to the strictest bundle, so a
    /// client that cannot satisfy it is refused here like any other - the refusal is not special.
    /// </summary>
    [Fact]
    public async Task StoredClientCarriesAProfileThisServerDoesNotDefine_ShouldReturnNull()
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = (ClientSecurityProfile)7,
        });

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        Assert.Null(result);
    }

    /// <summary>
    /// And a client that DOES satisfy the strictest bundle is served, which is what keeps the
    /// refusal in <see cref="StoredClientCarriesAProfileThisServerDoesNotDefine_ShouldReturnNull"/> from
    /// being "an undefined profile refuses everything" - a reading under which
    /// the value would be a denial of service rather than a constraint.
    /// </summary>
    [Fact]
    public async Task StoredClientWithAnUndefinedProfileButCompliant_ShouldAuthenticate()
    {
        var (authenticator, inner) = CreateAuthenticator();
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = (ClientSecurityProfile)7,
            // The strictest bundle admits only the FAPI signature algorithms for what the server signs for the client
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            TlsClientCertificateBoundAccessTokens = true,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        Assert.Same(clientInfo, result);
    }

    /// <summary>
    /// A registration the profile admits passes through untouched, which is what keeps the refusals in
    /// <see cref="StoredClientCannotSatisfyProfile_ShouldReturnNull"/> and
    /// <see cref="StoredClientAllowsAForbiddenResponseType_ShouldReturnNull"/> from being a decorator that
    /// refuses everything.
    /// </summary>
    [Fact]
    public async Task StoredClientSatisfiesProfile_ShouldAuthenticate()
    {
        var (authenticator, inner) = CreateAuthenticator();
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            // FAPI 2.0 section 5.4.1 admits no RS256 in what the server signs for the client
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest());

        Assert.Same(clientInfo, result);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.2 has access tokens sender-constrained via MTLS only, so a stored client requiring
    /// DPoP (RFC 9449 section 5.2), or one no certificate-bound token can be issued to, does not authenticate.
    /// </summary>
    [Theory]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    [InlineData(false, true, true)]
    public async Task UnderFapi1Advanced_AClientNoCertificateBoundTokenServes_DoesNotAuthenticate(
        bool requireDPoP, bool certificateBound, bool authenticated)
    {
        var (authenticator, inner) = CreateAuthenticator();
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            RequireDPoP = requireDPoP,
            TlsClientCertificateBoundAccessTokens = certificateBound,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.Fapi1Advanced), new ClientRequest());

        Assert.Equal(authenticated, result is not null);
    }

    /// <summary>
    /// Without a profile nothing is narrowed, so a deployment that selects none keeps every client
    /// it already had.
    /// </summary>
    [Fact]
    public async Task NoProfile_ShouldAuthenticateWhateverTheRegistration()
    {
        var (authenticator, inner) = CreateAuthenticator();
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest());

        Assert.Same(clientInfo, result);
    }

    /// <summary>
    /// The client's profile adds to the deployment's and never replaces it, in both directions: a
    /// shared-secret client is refused under a Fapi2 server whether it names the empty profile or
    /// names none at all, and equally when it names Fapi2 under a server that names nothing.
    /// </summary>
    /// <remarks>
    /// The second half is what keeps this from being satisfied by a decorator reading the
    /// deployment alone; the first is what keeps a registration from stepping out from under it.
    /// </remarks>
    [Fact]
    public async Task TheClientProfileAddsToTheDefaultRatherThanReplacingIt()
    {
        var (underFloor, underFloorInner) = CreateAuthenticator();
        Authenticates(underFloorInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        Assert.Null(await underFloor.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest()));

        var (tightened, tightenedInner) = CreateAuthenticator();
        Authenticates(tightenedInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.Fapi2,
        });

        Assert.Null(await tightened.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest()));
    }

    /// <summary>
    /// And a shared-secret client under a server naming no profile is accepted, without which the
    /// <see cref="TheClientProfileAddsToTheDefaultRatherThanReplacingIt"/> would be satisfied by a decorator
    /// refusing every shared-secret client.
    /// </summary>
    [Fact]
    public async Task NoProfileEitherSide_LeavesASharedSecretClientAlone()
    {
        var (unprofiled, unprofiledInner) = CreateAuthenticator();
        Authenticates(unprofiledInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        Assert.NotNull(await unprofiled.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.None), new ClientRequest()));
    }

    /// <summary>
    /// A credential that did not verify stays unverified: the decorator adds a refusal and never an
    /// acceptance.
    /// </summary>
    [Fact]
    public async Task InnerRefuses_ShouldReturnNull()
    {
        var (authenticator, inner) = CreateAuthenticator();
        inner.Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        Assert.Null(await authenticator.TryAuthenticateClientAsync(TenantAt(ClientSecurityProfile.Fapi2), new ClientRequest()));
    }

    /// <summary>
    /// A logger that keeps what it was told, STATE included. Hand-written rather than mocked because
    /// the type under test is internal, and a dynamic proxy cannot be built over a generic logger
    /// closed on it.
    /// </summary>
    /// <remarks>
    /// Without the state nothing here can tell an enum in a structured field from prose in it, or
    /// either from a field that is absent - so a decision about what a field carries would rest on
    /// reading rather than on a run.
    ///
    /// The cast falls back to an empty list, which is what a case asserting a field is ABSENT would
    /// be satisfied by if the generator's state type ever stopped carrying the interface. What stops
    /// that is the assertion beside it in
    /// <see cref="TheRefusal_ForAClientNamingNothing_CarriesNoProfileFieldAndItsOwnEventId"/>, naming a
    /// field that must be PRESENT on the same entry: it goes red on an empty list, so it is the control
    /// for the absence rather than a repetition of the assertion that the field is absent.
    /// </remarks>
    private sealed class CapturingLogger : ILogger<SecurityProfileClientAuthenticator>
    {
        public List<(LogLevel Level, int EventId, string Message, IReadOnlyList<KeyValuePair<string, object?>> Fields)>
            Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((
                logLevel,
                eventId.Id,
                formatter(state, exception),
                state as IReadOnlyList<KeyValuePair<string, object?>> ?? []));
    }

    /// <summary>
    /// A stored client at the RS256 defaults, met under a FAPI 1.0 Advanced tenant, is refused where it authenticates:
    /// the server would sign its ID tokens with an algorithm FAPI 1.0 Part 2 section 8.6 does not name.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    public async Task StoredClientSignedForOutsideTheFapiAlgorithms_ShouldReturnNull(string algorithm, bool accepted)
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdentityTokenSignedResponseAlgorithm = algorithm,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            TlsClientCertificateBoundAccessTokens = true,
        });

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.Fapi1Advanced), new ClientRequest());

        Assert.Equal(accepted, result != null);
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2: "shall return an invalid_client error as defined in 5.2 of RFC6749 when
    /// mis-matched client identifiers were provided through the client authentication methods that permits sending the
    /// client identifier in more than one way". A client held to FAPI 1.0 Advanced whose request names another
    /// client_id than the one its credential proves is refused; naming its own, or none, passes, and a client held to
    /// no profile is left to what the credential proves.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, "someone-else", false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, ClientId, true)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, null, true)]
    [InlineData(null, "someone-else", true)]
    public async Task AMismatchedClientId_IsRefused(ClientSecurityProfile? profile, string? named, bool accepted)
    {
        var (authenticator, inner) = CreateAuthenticator();
        Authenticates(inner, new ClientInfo(ClientId)
        {
            SecurityProfile = profile,
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            TlsClientCertificateBoundAccessTokens = true,
        });

        var result = await authenticator.TryAuthenticateClientAsync(
            TenantAt(ClientSecurityProfile.None), new ClientRequest { ClientId = named });

        Assert.Equal(accepted, result != null);
    }
}
