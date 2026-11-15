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
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The client configuration endpoint (RFC 7592 section 2.2) and the registration endpoint requiring an initial access
/// token (RFC 7591 section 3) are protected resources, and a request reaching either without a usable token "does not
/// contain an access token that enables access", which RFC 6750 section 3 has answered with the WWW-Authenticate
/// field. Its body is judged only once the token passes, so whatever the body is, a request without a token learns
/// that it needs one.
/// </summary>
public class ClientMetadataBodyAfterTheTokenTests(TestFactory factory) : TestBase(factory)
{
    private const string RealmAttribute = "realm";

    // A media type the framework's JSON reader takes beside application/json
    private const string TextJson = "text/json";

    private const string NotJson = nameof(NotJson);
    private const string RedirectUrisNotAnArray = nameof(RedirectUrisNotAnArray);
    private const string TextPlain = nameof(TextPlain);
    private const string NoMediaType = nameof(NoMediaType);
    private const string NotAMediaType = nameof(NotAMediaType);
    private const string UndecodableCharset = nameof(UndecodableCharset);
    private const string DeclaredOverTheBound = nameof(DeclaredOverTheBound);
    private const string ChunkedOverTheBound = nameof(ChunkedOverTheBound);

    private const string NoToken = nameof(NoToken);
    private const string ValidToken = nameof(ValidToken);
    private const string OpenRegistration = nameof(OpenRegistration);

    public static TheoryData<string, string, string> Requests()
    {
        var data = new TheoryData<string, string, string>();
        string[] bodies =
        [
            NotJson, RedirectUrisNotAnArray, TextPlain, NoMediaType, NotAMediaType, UndecodableCharset,
#if !MINIMAL_API_TRANSPORT
            // The Minimal API host leaves the bound to the server, which the in-memory test server does not enforce
            DeclaredOverTheBound, ChunkedOverTheBound,
#endif
        ];
        foreach (var body in bodies)
        {
            data.Add("PUT", body, NoToken);
            data.Add("PUT", body, ValidToken);
            data.Add("POST", body, NoToken);
            data.Add("POST", body, ValidToken);
            data.Add("POST", body, OpenRegistration);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task The_body_is_judged_only_once_the_token_passes(string method, string body, string token)
    {
        var requireInitialAccessToken = method == HttpMethod.Post.Method && token != OpenRegistration;
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.RequireInitialAccessToken = requireInitialAccessToken))));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);

        Uri target;
        string? credentials;
        if (method == HttpMethod.Put.Method)
        {
            // The client to update is registered first, which this host, requiring no initial access token, allows
            var registered = await RegisterClientAsync(client, discovery, new JsonObject
            {
                [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            });
            target = new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>());
            credentials = registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();
        }
        else
        {
            target = discovery.RegistrationEndpoint!;
            var issued = await host.Services.GetRequiredService<IInitialAccessTokenService>().IssueTokenAsync(
                TestTenant.Of(host.Services),
                "registration-portal",
                host.Services.GetRequiredService<TimeProvider>().GetUtcNow(),
                TimeSpan.FromMinutes(5));
            credentials = issued.EncodedJwt;
        }

        using var request = new HttpRequestMessage(new HttpMethod(method), target) { Content = Body(host.Services, body) };
        if (token == ValidToken)
            request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, credentials);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        if (token == NoToken)
        {
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{(int)response.StatusCode}: {raw}");
            var challenge = ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString());
            Assert.Equal(TokenTypes.Bearer, challenge.Scheme);
            Assert.Equal(
                [new KeyValuePair<string, string>(RealmAttribute, discovery.Issuer.OriginalString)],
                challenge.Parameters);
            return;
        }

        // A request whose token passes, or one at an endpoint asking for none, gets the body's own refusal
        Assert.True(response.StatusCode == BodyRefusal(body), $"{(int)response.StatusCode}: {raw}");
        Assert.Empty(response.Headers.WwwAuthenticate);
        if (BodyRefusal(body) == HttpStatusCode.BadRequest)
        {
            Assert.Equal(
                ErrorCodes.InvalidClientMetadata,
                JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>());
        }
    }

    /// <summary>
    /// A body of a media type the metadata is not read in is refused without being read, even where a JSON reader
    /// of the framework takes that media type too: read ahead of the token, a body up to the server's own limit
    /// would be parsed for a caller with no token at all.
    /// </summary>
    [Fact]
    public async Task A_body_of_another_media_type_is_never_read()
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.RequireInitialAccessToken = true))));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);

        var limit = host.Services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;
        Assert.NotNull(limit);

        // Several times the bound, without a declared length, in a media type the framework's JSON reader also takes
        var body = new MeteredJsonStream(RequestMembers.ClientName, limit.Value * 4);
        using var content = new StreamContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(TextJson);
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.RegistrationEndpoint) { Content = content };

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // The in-memory transport pulls part of an unread body ahead by itself, so the ceiling is the bound, which a
        // read bounded by it still crosses by the one byte it takes to tell the body is over it
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(body.Produced <= limit.Value, $"{body.Produced} bytes of the body were read");
    }

    private static HttpStatusCode BodyRefusal(string body) => body switch
    {
        NotJson or RedirectUrisNotAnArray => HttpStatusCode.BadRequest,
        TextPlain or NoMediaType or NotAMediaType or UndecodableCharset => HttpStatusCode.UnsupportedMediaType,
        DeclaredOverTheBound or ChunkedOverTheBound => HttpStatusCode.RequestEntityTooLarge,
        _ => throw new ArgumentOutOfRangeException(nameof(body), body, null),
    };

    private static HttpContent Body(IServiceProvider services, string body)
    {
        var metadata = $$"""{"{{RequestMembers.RedirectUris}}": ["{{TestConstants.RedirectUri}}"]}""";
        switch (body)
        {
            case NotJson:
                return new StringContent("not json", Encoding.UTF8, MediaTypeNames.Application.Json);

            case RedirectUrisNotAnArray:
                return new StringContent(
                    $$"""{"{{RequestMembers.RedirectUris}}": 5}""", Encoding.UTF8, MediaTypeNames.Application.Json);

            case TextPlain:
                return new StringContent(metadata, Encoding.UTF8, MediaTypeNames.Text.Plain);

            case NoMediaType:
                return new ByteArrayContent(Encoding.UTF8.GetBytes(metadata));

            case NotAMediaType:
                var unparsed = new ByteArrayContent(Encoding.UTF8.GetBytes(metadata));
                Assert.True(unparsed.Headers.TryAddWithoutValidation("Content-Type", "not a media type"));
                return unparsed;

            case UndecodableCharset:
                var content = new ByteArrayContent(Encoding.UTF8.GetBytes(metadata));
                content.Headers.ContentType = MediaTypeHeaderValue.Parse(MediaTypeNames.Application.Json + "; charset=bogus");
                return content;

            case DeclaredOverTheBound:
                var limit = services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;
                Assert.NotNull(limit);
                return new StringContent(
                    $$"""{"{{RequestMembers.ClientName}}": "{{new string('a', (int)limit.Value)}}"}""",
                    Encoding.UTF8,
                    MediaTypeNames.Application.Json);

            case ChunkedOverTheBound:
                // No declared length, so the bound is known to be passed only by reading one byte past it
                var bound = services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;
                Assert.NotNull(bound);
                var chunked = new StreamContent(new MeteredJsonStream(RequestMembers.ClientName, bound.Value + 1));
                chunked.Headers.ContentType = new MediaTypeHeaderValue(MediaTypeNames.Application.Json);
                return chunked;

            default:
                throw new ArgumentOutOfRangeException(nameof(body), body, null);
        }
    }
}
