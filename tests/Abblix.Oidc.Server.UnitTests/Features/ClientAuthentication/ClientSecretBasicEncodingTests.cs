// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// RFC 6749 section 2.3.1: "The client identifier is encoded using the "application/x-www-form-urlencoded" encoding
/// algorithm per Appendix B, and the encoded value is used as the username; the client password is encoded using the
/// same algorithm and used as the password", so each half is decoded after the split at the first colon.
/// </summary>
public class ClientSecretBasicEncodingTests
{
    /// <summary>
    /// A client authenticating with <paramref name="clientId"/> and <paramref name="secret"/>, written into the Basic
    /// credentials as <paramref name="userId"/> and <paramref name="password"/>.
    /// </summary>
    private static async Task<bool> AuthenticatesAsync(
        string clientId, string secret, string userId, string password, string? namedInTheBody = null)
    {
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(p => p.FindClientAsync(TestTenant.Matched, clientId))
            .ReturnsAsync(new ClientInfo(clientId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
                ClientSecrets = [new ClientSecret { Sha512Hash = TestSecretHasher.HashSecret(secret) }],
            });
        clients
            .Setup(p => p.FindClientAsync(TestTenant.Matched, It.Is<string>(id => id != clientId)))
            .ReturnsAsync(ClientAbsence.Unknown);

        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{userId}:{password}"));
        var request = new ClientRequest
        {
            ClientId = namedInTheBody,
            AuthorizationHeaderLines = [new AuthenticationHeaderValue(TokenTypes.Basic, credentials).ToString()],
        };

        var result = await new ClientSecretBasicAuthenticator(
                NullLogger<ClientSecretBasicAuthenticator>.Instance, TimeProvider.System, new HashService())
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, request, clients.Object);
        return result.TryGetSuccess(out _);
    }

    /// <summary>
    /// The worked example of RFC 6749 Appendix B: the six code points space, percent, ampersand, plus, pound and euro
    /// are "represented in the payload as: +%25%26%2B%C2%A3%E2%82%AC".
    /// </summary>
    [Fact]
    public void TheAppendixBExampleDecodesToItsSixCodePoints()
    {
        Assert.True(FormUrlEncoding.TryDecode("+%25%26%2B%C2%A3%E2%82%AC", out var decoded));
        Assert.Equal(" %&+£€", decoded);
    }

    /// <summary>
    /// A non-ASCII secret is hashed as its UTF-8 octets, as a standard digest tool computes the hash a host declares, so
    /// it authenticates against that hash.
    /// </summary>
    [Theory]
    [InlineData("pass£", "pass%C2%A3", true)]
    [InlineData(" %&+£€", "+%25%26%2B%C2%A3%E2%82%AC", true)]
    public async Task ANonAsciiSecretIsHashedAsItsUtf8Octets(string secret, string password, bool authenticates)
    {
        Assert.Equal(authenticates, await AuthenticatesAsync("client", secret, "client", password));
    }

    /// <summary>
    /// A secret holding a plus sign or a percent sign is sent encoded; sent raw it names another secret: a plus sign
    /// stands for a space, and a percent sign begins an escape.
    /// </summary>
    [Theory]
    [InlineData("a+b", "a%2Bb", true)]
    [InlineData("a+b", "a+b", false)]
    [InlineData("a b", "a+b", true)]
    [InlineData("50%off", "50%25off", true)]
    public async Task ASecretIsDecodedFromTheFormEncoding(string secret, string password, bool authenticates)
    {
        Assert.Equal(authenticates, await AuthenticatesAsync("client", secret, "client", password));
    }

    /// <summary>
    /// A client identifier holding a colon, such as a URN, is sent with the colon encoded, so the first colon in the
    /// credentials still parts the identifier from the secret (RFC 7617 section 2).
    /// </summary>
    [Fact]
    public async Task AClientIdentifierHoldingAColonAuthenticates()
    {
        Assert.True(await AuthenticatesAsync("urn:example:client", "secret", "urn%3Aexample%3Aclient", "secret"));
    }

    /// <summary>
    /// FAPI 1.0 Part 1 section 5.2.2, which this server holds every client to: a client_id in the body naming another
    /// client than the Basic credentials identify is refused, whatever the credentials prove.
    /// </summary>
    [Theory]
    [InlineData("someone-else", false)]
    [InlineData("client", true)]
    [InlineData(null, true)]
    public async Task ABodyClientIdNamingAnotherClient_IsRefused(string? named, bool accepted)
    {
        Assert.Equal(accepted, await AuthenticatesAsync("client", "secret", "client", "secret", named));
    }

    /// <summary>
    /// A percent sign without two hexadecimal digits, or escapes that are not UTF-8, decode to nothing: the credential
    /// is refused rather than read as some other secret.
    /// </summary>
    [Theory]
    [InlineData("%zz")]
    [InlineData("abc%")]
    [InlineData("abc%4")]
    [InlineData("%C3")]
    [InlineData("%C3%28")]
    public async Task AMalformedEscapeIsRefused(string password)
    {
        Assert.False(FormUrlEncoding.TryDecode(password, out _));
        Assert.False(await AuthenticatesAsync("client", password, "client", password));
    }
}
