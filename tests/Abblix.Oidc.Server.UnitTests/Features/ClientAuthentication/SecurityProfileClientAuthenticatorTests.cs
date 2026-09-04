// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
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

    private static (SecurityProfileClientAuthenticator Authenticator, Mock<IClientAuthenticator> Inner)
        CreateAuthenticator(ClientSecurityProfile defaultProfile)
        => CreateAuthenticator(defaultProfile, NullLogger<SecurityProfileClientAuthenticator>.Instance);

    private static (SecurityProfileClientAuthenticator Authenticator, Mock<IClientAuthenticator> Inner)
        CreateAuthenticator(ClientSecurityProfile defaultProfile, ILogger<SecurityProfileClientAuthenticator> logger)
    {
        var inner = new Mock<IClientAuthenticator>();
        var authenticator = new SecurityProfileClientAuthenticator(
            inner.Object,
            Options.Create(new OidcOptions { DefaultSecurityProfile = defaultProfile }),
            logger);

        return (authenticator, inner);
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

        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.None, logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = (ClientSecurityProfile)7,
        });

        await authenticator.TryAuthenticateClientAsync(new ClientRequest());

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

        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2, logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyProfile);

        Assert.Contains(nameof(ClientSecurityProfile.None), entry.Message);
        Assert.Contains(nameof(ClientSecurityProfile.Fapi2), entry.Message);
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

        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2, logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        });

        await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        var entry = Assert.Single(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .RegistrationCannotSatisfyProfile);

        Assert.DoesNotContain("null", entry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(nameof(ClientSecurityProfile.Fapi2), entry.Message);
    }

    /// <summary>
    /// And a profile this server does define says nothing, or the line would be noise on every
    /// request rather than a signal about one client.
    /// </summary>
    [Fact]
    public async Task StoredClientWithADefinedProfile_ShouldNotBeNamedInTheLog()
    {
        var logger = new CapturingLogger();

        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.None, logger);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = ClientSecurityProfile.Fapi2,
        });

        await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        Assert.DoesNotContain(
            logger.Entries,
            e => e.EventId == LogEvents.ClientAuth.SecurityProfileClientAuthenticator
                .ProfileIsNotOneThisServerDefines);
    }

    private static void Authenticates(Mock<IClientAuthenticator> inner, ClientInfo clientInfo)
        => inner.Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
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
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        Authenticates(inner, new ClientInfo(ClientId) { TokenEndpointAuthMethod = method });

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

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
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            // The code response type is allowed as well, so this trips the clause about a
            // FORBIDDEN response type and no other: an array carrying only the hybrid pair would
            // also trip the clause requiring the code type, and the row would stay green if the
            // clause its name points at were deleted.
            AllowedResponseTypes = [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
        });

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

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
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.None);
        Authenticates(inner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = (ClientSecurityProfile)7,
        });

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        Assert.Null(result);
    }

    /// <summary>
    /// And a client that DOES satisfy the strictest bundle is served, which is what keeps the
    /// refusal above from being "an undefined profile refuses everything" - a reading under which
    /// the value would be a denial of service rather than a constraint.
    /// </summary>
    [Fact]
    public async Task StoredClientWithAnUndefinedProfileButCompliant_ShouldAuthenticate()
    {
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.None);
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            SecurityProfile = (ClientSecurityProfile)7,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        Assert.Same(clientInfo, result);
    }

    /// <summary>
    /// A registration the profile admits passes through untouched, which is what keeps the refusals
    /// above from being a decorator that refuses everything.
    /// </summary>
    [Fact]
    public async Task StoredClientSatisfiesProfile_ShouldAuthenticate()
    {
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

        Assert.Same(clientInfo, result);
    }

    /// <summary>
    /// Without a profile nothing is narrowed, so a deployment that selects none keeps every client
    /// it already had.
    /// </summary>
    [Fact]
    public async Task NoProfile_ShouldAuthenticateWhateverTheRegistration()
    {
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.None);
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
        };
        Authenticates(inner, clientInfo);

        var result = await authenticator.TryAuthenticateClientAsync(new ClientRequest());

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
        var (underFloor, underFloorInner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        Authenticates(underFloorInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        Assert.Null(await underFloor.TryAuthenticateClientAsync(new ClientRequest()));

        var (tightened, tightenedInner) = CreateAuthenticator(ClientSecurityProfile.None);
        Authenticates(tightenedInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.Fapi2,
        });

        Assert.Null(await tightened.TryAuthenticateClientAsync(new ClientRequest()));
    }

    /// <summary>
    /// And a shared-secret client under a server naming no profile is accepted, without which the
    /// case above would be satisfied by a decorator refusing every shared-secret client.
    /// </summary>
    [Fact]
    public async Task NoProfileEitherSide_LeavesASharedSecretClientAlone()
    {
        var (unprofiled, unprofiledInner) = CreateAuthenticator(ClientSecurityProfile.None);
        Authenticates(unprofiledInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        Assert.NotNull(await unprofiled.TryAuthenticateClientAsync(new ClientRequest()));
    }

    /// <summary>
    /// A credential that did not verify stays unverified: the decorator adds a refusal and never an
    /// acceptance.
    /// </summary>
    [Fact]
    public async Task InnerRefuses_ShouldReturnNull()
    {
        var (authenticator, inner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        inner.Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        Assert.Null(await authenticator.TryAuthenticateClientAsync(new ClientRequest()));
    }

    /// <summary>
    /// A logger that keeps what it was told. Hand-written rather than mocked because the type under
    /// test is internal, and a dynamic proxy cannot be built over a generic logger closed on it.
    /// </summary>
    private sealed class CapturingLogger : ILogger<SecurityProfileClientAuthenticator>
    {
        public List<(LogLevel Level, int EventId, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId.Id, formatter(state, exception)));
    }
}
