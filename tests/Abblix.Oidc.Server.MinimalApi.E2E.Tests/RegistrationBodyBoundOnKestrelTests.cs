// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The registration and client configuration endpoints leave the bound on the body to the server, which the in-memory
/// test server does not enforce, so this suite runs the host on Kestrel. A body over the bound is refused only once the
/// token passes: the registration endpoint requiring an initial access token (RFC 7591 section 3) and the client
/// configuration endpoint (RFC 7592 section 2.2) are protected resources, and RFC 6750 section 3 has a request without
/// a token enabling access answered with the WWW-Authenticate field, whatever its body holds.
/// </summary>
public sealed class RegistrationBodyBoundOnKestrelTests : IAsyncLifetime
{
    private const string RealmAttribute = "realm";

    // The key purpose of a TLS server certificate (RFC 5280 section 4.2.1.12, id-kp-serverAuth)
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";

    private const string DeclaredOverTheBound = nameof(DeclaredOverTheBound);
    private const string ChunkedOverTheBound = nameof(ChunkedOverTheBound);

    private const string NoToken = nameof(NoToken);
    private const string InvalidToken = nameof(InvalidToken);
    private const string ValidToken = nameof(ValidToken);

    private X509Certificate2? _certificate;
    private TestFactory? _factory;
    private HttpClient? _client;
    private Uri? _address;

    private IServiceProvider Services { get; set; } = null!;

    public ValueTask InitializeAsync()
    {
        _certificate = SelfSignedCertificate(TimeProvider.System);

        _factory = new TestFactory();
        var factory = _factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.RequireInitialAccessToken = true))));
        factory.UseKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(_certificate)));
        factory.StartServer();
        Services = factory.Services;

        var addresses = Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
        Assert.NotNull(addresses);
        _address = new Uri(Assert.Single(addresses.Addresses));

        // Only the certificate this test made is trusted, and only by this client
        var pinned = _certificate.GetCertHash(HashAlgorithmName.SHA256);
        _client = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, presented, _, _) =>
                    presented is not null && presented.GetCertHash(HashAlgorithmName.SHA256).AsSpan().SequenceEqual(pinned),
            },
        });

        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _client?.Dispose();
        if (_factory is not null)
            await _factory.DisposeAsync();
        _certificate?.Dispose();
    }

    public static TheoryData<string, string, string> Requests()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var method in new[] { "POST", "PUT" })
        {
            foreach (var body in new[] { DeclaredOverTheBound, ChunkedOverTheBound })
            {
                foreach (var token in new[] { NoToken, InvalidToken, ValidToken })
                    data.Add(method, body, token);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task A_body_over_the_bound_is_refused_only_once_the_token_passes(
        string method, string body, string token)
    {
        var routes = Services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var initialAccessToken = await IssueInitialAccessTokenAsync();

        string path;
        string credentials;
        if (method == HttpMethod.Post.Method)
        {
            path = routes.Register;
            credentials = initialAccessToken;
        }
        else
        {
            var registered = await RegisterClientAsync(routes.Register, initialAccessToken);
            path = new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>()).PathAndQuery;
            credentials = registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();
        }

        using var request = Request(new HttpMethod(method), path);
        request.Content = Body(body);
        switch (token)
        {
            case ValidToken:
                request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, credentials);
                break;

            case InvalidToken:
                // The token the endpoint issued, one character short, so it no longer validates
                request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, credentials[..^1]);
                break;

            case NoToken:
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(token), token, null);
        }

        using var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        switch (token)
        {
            case NoToken:
                Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{(int)response.StatusCode}: {raw}");
                ChallengeAssert.Carries(
                    ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString()),
                    TokenTypes.Bearer,
                    (RealmAttribute, TestTenant.Of(Services).Issuer.OriginalString));
                break;

            case InvalidToken:
                Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{(int)response.StatusCode}: {raw}");
                ChallengeAssert.Carries(
                    ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString()),
                    TokenTypes.Bearer,
                    (ErrorResponse.Parameters.Error, ErrorCodes.InvalidToken),
                    (ErrorResponse.Parameters.ErrorDescription, null));
                break;

            case ValidToken:
                Assert.True(
                    response.StatusCode == HttpStatusCode.RequestEntityTooLarge, $"{(int)response.StatusCode}: {raw}");
                Assert.Empty(response.Headers.WwwAuthenticate);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(token), token, null);
        }
    }

    /// <summary>
    /// A request to the server on Kestrel naming the issuer's host, since a request reaches a tenant by the host its
    /// issuer names.
    /// </summary>
    private HttpRequestMessage Request(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, new Uri(_address!, path));
        request.Headers.Host = TestFactory.BaseAddress.Authority;
        return request;
    }

    private async Task<string> IssueInitialAccessTokenAsync()
    {
        var issued = await Services.GetRequiredService<IInitialAccessTokenService>().IssueTokenAsync(
            TestTenant.Of(Services),
            "registration-portal",
            Services.GetRequiredService<TimeProvider>().GetUtcNow(),
            TimeSpan.FromMinutes(5));
        return issued.EncodedJwt;
    }

    private async Task<JsonObject> RegisterClientAsync(string path, string initialAccessToken)
    {
        using var request = Request(HttpMethod.Post, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, initialAccessToken);
        request.Content = new StringContent(
            $$"""{"{{RequestMembers.RedirectUris}}": ["https://client.example.com/callback"]}""",
            Encoding.UTF8,
            MediaTypeNames.Application.Json);

        using var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Created, $"{(int)response.StatusCode}: {raw}");
        return JsonNode.Parse(raw)!.AsObject();
    }

    private HttpContent Body(string body)
    {
        var bound = Services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;
        Assert.NotNull(bound);

        switch (body)
        {
            case DeclaredOverTheBound:
                return new StringContent(
                    $$"""{"{{RequestMembers.ClientName}}": "{{new string('a', (int)bound.Value)}}"}""",
                    Encoding.UTF8,
                    MediaTypeNames.Application.Json);

            case ChunkedOverTheBound:
                // No declared length, so the bound is known to be passed only by reading one byte past it
                var chunked = new StreamContent(new MeteredJsonStream(RequestMembers.ClientName, bound.Value + 1));
                chunked.Headers.ContentType = new MediaTypeHeaderValue(MediaTypeNames.Application.Json);
                return chunked;

            default:
                throw new ArgumentOutOfRangeException(nameof(body), body, null);
        }
    }

    /// <summary>
    /// A certificate for the loopback address, made for this test alone. Exported and loaded again, since the
    /// platform's TLS stack needs its private key in a form an ephemeral key does not give on every platform.
    /// </summary>
    private static X509Certificate2 SelfSignedCertificate(TimeProvider clock)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        names.AddDnsName("localhost");
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid(ServerAuthentication)], critical: false));

        var now = clock.GetUtcNow();
        using var created = request.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), password: null);
    }
}
