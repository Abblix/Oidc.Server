// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
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
    {
        var inner = new Mock<IClientAuthenticator>();
        var authenticator = new SecurityProfileClientAuthenticator(
            inner.Object,
            Options.Create(new OidcOptions { DefaultSecurityProfile = defaultProfile }),
            NullLogger<SecurityProfileClientAuthenticator>.Instance);

        return (authenticator, inner);
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
    /// The client's own profile outranks the server-wide default, in both directions: a client
    /// naming no profile under a Fapi2 server is held to it, and a client naming none under one is
    /// not. Without the second half the decorator could be reading the default alone.
    /// </summary>
    [Fact]
    public async Task ClientProfileOverridesTheDefault()
    {
        var (relaxed, relaxedInner) = CreateAuthenticator(ClientSecurityProfile.Fapi2);
        Authenticates(relaxedInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.None,
        });

        Assert.NotNull(await relaxed.TryAuthenticateClientAsync(new ClientRequest()));

        var (tightened, tightenedInner) = CreateAuthenticator(ClientSecurityProfile.None);
        Authenticates(tightenedInner, new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
            SecurityProfile = ClientSecurityProfile.Fapi2,
        });

        Assert.Null(await tightened.TryAuthenticateClientAsync(new ClientRequest()));
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
}
