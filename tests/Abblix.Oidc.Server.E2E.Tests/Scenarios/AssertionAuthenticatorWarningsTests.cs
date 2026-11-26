// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The token endpoint asks both assertion authenticators about a client assertion, since the request does not say
/// which method its client registered. An assertion is answered by the authenticator its signature belongs to: a
/// client authenticating as it registered logs no warning, and a refused assertion warns once, from one of them.
/// </summary>
public class AssertionAuthenticatorWarningsTests(TestFactory factory) : TestBase(factory)
{
    private const string PrivateKeyJwtClient = "private_key_jwt";
    private const string ClientSecretJwtClient = "client_secret_jwt";

    private const string OwnKey = "own key";
    private const string ForeignKey = "foreign key";
    private const string OwnSecret = "own secret";
    private const string ForeignSecret = "foreign secret";
    private const string Unsigned = "unsigned";
    private const string UnknownAlgorithm = "unknown algorithm";

    private static readonly string PrivateKeyJwtCategory = typeof(PrivateKeyJwtAuthenticator).FullName!;
    private static readonly string ClientSecretJwtCategory = typeof(ClientSecretJwtAuthenticator).FullName!;

    /// <summary>
    /// A client signing its assertion as it registered is issued a token, and nothing in the server warns about it:
    /// the authenticator of the other method does not read an assertion signed otherwise than it signs.
    /// </summary>
    [Theory]
    [InlineData(PrivateKeyJwtClient, OwnKey)]
    [InlineData(ClientSecretJwtClient, OwnSecret)]
    public async Task AnAssertionSignedAsTheClientRegistered_LogsNoWarning(string client, string signer)
    {
        var (status, warnings) = await PresentAsync(client, signer);

        Assert.True(status.IsSuccessStatusCode, $"{(int)status.StatusCode}");
        Assert.DoesNotContain(warnings, entry => entry.Category.StartsWith(nameof(Abblix), StringComparison.Ordinal));
    }

    /// <summary>
    /// An assertion refused by the authenticator of its own method warns from that authenticator alone.
    /// </summary>
    [Theory]
    [InlineData(PrivateKeyJwtClient, ForeignKey, nameof(PrivateKeyJwtAuthenticator))]
    [InlineData(ClientSecretJwtClient, ForeignSecret, nameof(ClientSecretJwtAuthenticator))]
    public async Task AnAssertionRefusedByItsOwnMethod_WarnsOnceFromThatAuthenticator(
        string client, string signer, string owner)
    {
        var (status, warnings) = await PresentAsync(client, signer);

        await AssertInvalidClientAsync(status);
        var (ownerCategory, otherCategory) = owner == nameof(PrivateKeyJwtAuthenticator)
            ? (PrivateKeyJwtCategory, ClientSecretJwtCategory)
            : (ClientSecretJwtCategory, PrivateKeyJwtCategory);
        Assert.Single(warnings, entry => entry.Category == ownerCategory);
        Assert.DoesNotContain(warnings, entry => entry.Category == otherCategory);
    }

    /// <summary>
    /// An assertion signed as the other method signs is refused with the same error, and still warns once, from the
    /// authenticator its signature belongs to: neither authenticator answering it would turn the refusal into a
    /// request presenting no credential.
    /// </summary>
    [Theory]
    [InlineData(PrivateKeyJwtClient, OwnSecret)]
    [InlineData(ClientSecretJwtClient, OwnKey)]
    public async Task AnAssertionSignedAsTheOtherMethodSigns_IsRefusedAndWarnsOnce(string client, string signer)
    {
        var (status, warnings) = await PresentAsync(client, signer);

        await AssertInvalidClientAsync(status);
        Assert.Single(
            warnings,
            entry => entry.Category == PrivateKeyJwtCategory || entry.Category == ClientSecretJwtCategory);
    }

    /// <summary>
    /// An assertion signed with an algorithm neither method signs with is refused with the same error, and warns once,
    /// from private_key_jwt, which reads it: client_secret_jwt claims its HS algorithms alone.
    /// </summary>
    [Theory]
    [InlineData(PrivateKeyJwtClient, Unsigned)]
    [InlineData(PrivateKeyJwtClient, UnknownAlgorithm)]
    [InlineData(ClientSecretJwtClient, Unsigned)]
    [InlineData(ClientSecretJwtClient, UnknownAlgorithm)]
    public async Task AnAssertionSignedWithNoMethodsAlgorithm_IsRefusedAndWarnsOnceFromPrivateKeyJwt(
        string client, string signer)
    {
        var (status, warnings) = await PresentAsync(client, signer);

        await AssertInvalidClientAsync(status);
        Assert.Single(warnings, entry => entry.Category == PrivateKeyJwtCategory);
        Assert.DoesNotContain(warnings, entry => entry.Category == ClientSecretJwtCategory);
    }

    /// <summary>
    /// Posts a client_credentials token request of <paramref name="client"/> authenticated by an assertion
    /// <paramref name="signer"/> signs, and answers the response with the warnings the host logged while serving it.
    /// </summary>
    private async Task<(HttpResponseMessage Response, IReadOnlyList<(string Category, EventId EventId)> Warnings)>
        PresentAsync(string client, string signer)
    {
        var recorder = new WarningRecorder();
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ILoggerProvider>(recorder)));
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(http);
        var issuer = discovery.Issuer.OriginalString;

        var ownKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.PS256);
        var clientId = client switch
        {
            PrivateKeyJwtClient => await RegisterPrivateKeyJwtClientAsync(http, discovery, ownKey),
            ClientSecretJwtClient => TestConstants.ClientSecretJwtClientId,
            _ => throw new ArgumentOutOfRangeException(nameof(client), client, null),
        };
        var assertion = signer switch
        {
            OwnKey => await ClientSecretJwtAssertion.IssueWithKeyAsync(clientId, ownKey, issuer),
            ForeignKey => await ClientSecretJwtAssertion.IssueWithKeyAsync(
                clientId, JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.PS256), issuer),
            OwnSecret => await ClientSecretJwtAssertion.IssueWithSecretAsync(
                clientId, TestConstants.ClientSecretJwtSecret, issuer),
            ForeignSecret => await ClientSecretJwtAssertion.IssueWithSecretAsync(
                clientId, new string('x', TestConstants.ClientSecretJwtSecret.Length), issuer),
            Unsigned => UnverifiableAssertion(clientId, issuer, SigningAlgorithms.None),
            UnknownAlgorithm => UnverifiableAssertion(clientId, issuer, "XS512"),
            _ => throw new ArgumentOutOfRangeException(nameof(signer), signer, null),
        };

        // Only what the token request itself logs is judged
        recorder.Clear();
        var response = await FormPostHelpers.PostFormAsync(http, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] = assertion,
        });
        return (response, recorder.Warnings);
    }

    /// <summary>
    /// An assertion of <paramref name="clientId"/> whose header names <paramref name="algorithm"/>, with a signature
    /// no key verifies, as a client would send one signed with an algorithm this server does not take.
    /// </summary>
    private static string UnverifiableAssertion(string clientId, string issuer, string algorithm)
    {
        var now = TimeProvider.System.GetUtcNow();
        var header = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = algorithm,
            [JwtClaimTypes.Type] = JsonWebTokenTypes.ClientAuthentication,
        };
        var payload = new JsonObject
        {
            [JwtClaimTypes.JwtId] = Guid.NewGuid().ToString("N"),
            [JwtClaimTypes.Issuer] = clientId,
            [JwtClaimTypes.Subject] = clientId,
            [JwtClaimTypes.Audience] = issuer,
            [JwtClaimTypes.IssuedAt] = now.ToUnixTimeSeconds(),
            [JwtClaimTypes.ExpiresAt] = now.AddMinutes(1).ToUnixTimeSeconds(),
        };
        var signature = algorithm == SigningAlgorithms.None ? string.Empty : Encode("not a signature"u8.ToArray());
        return $"{Encode(Encoding.UTF8.GetBytes(header.ToJsonString()))}." +
               $"{Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()))}.{signature}";
    }

    private static string Encode(byte[] octets) => Base64Url.EncodeToString(octets);

    private static async Task AssertInvalidClientAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode, body);
        Assert.Equal(
            ErrorCodes.InvalidClient,
            JsonNode.Parse(body)![ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// Registers a private_key_jwt client verified with the public half of <paramref name="clientKey"/> and signing
    /// with PS256, allowed the client_credentials grant.
    /// </summary>
    private static async Task<string> RegisterPrivateKeyJwtClientAsync(
        HttpClient http, Model.DiscoveryDocument discovery, RsaJsonWebKey clientKey)
    {
        var registered = await RegisterClientAsync(http, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = $"private-key-jwt-{Guid.NewGuid():N}",
            [RegistrationMembers.ResponseTypes] = new JsonArray(),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
            [RegistrationMembers.TokenEndpointAuthSigningAlg] = SigningAlgorithms.PS256,
            [RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(
                new JsonWebKeySet([clientKey.Sanitize(includePrivateKeys: false)])),
        });

        return registered[ClientRegistrationResponse.Parameters.ClientId]!.GetValue<string>();
    }

    /// <summary>
    /// Keeps the category and event of every warning or worse the host logs.
    /// </summary>
    private sealed class WarningRecorder : ILoggerProvider
    {
        private readonly ConcurrentQueue<(string Category, EventId EventId)> _warnings = new();

        public IReadOnlyList<(string Category, EventId EventId)> Warnings => _warnings.ToArray();

        public void Clear() => _warnings.Clear();

        public ILogger CreateLogger(string categoryName) => new Recorder(_warnings, categoryName);

        public void Dispose()
        {
            // Nothing is held
        }

        private sealed class Recorder(ConcurrentQueue<(string Category, EventId EventId)> warnings, string category)
            : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (logLevel >= LogLevel.Warning)
                    warnings.Enqueue((category, eventId));
            }
        }
    }
}
