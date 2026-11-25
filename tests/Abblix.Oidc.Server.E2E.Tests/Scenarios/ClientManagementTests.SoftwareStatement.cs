// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

// A registration presenting a software statement from an issuer the server trusts is registered with the metadata the
// statement carries, over what the request body names (RFC 7591 sections 2 and 3.1.1), keeps it through an RFC 7592
// update, and is answered with the statement's values and the statement unmodified (RFC 7591 section 3.2.1)
public partial class ClientManagementTests
{
    private const string LegitRedirectUri = "https://legit.example.com/cb";
    private const string AttackerRedirectUri = "https://attacker.example.net/cb";

    /// <summary>
    /// The statement names one redirect URI and the body another: the stored client has the statement's alone, the
    /// response names it and returns the statement as presented, and an authorization request to the body's address
    /// is refused while one to the statement's is answered there.
    /// </summary>
    [Fact]
    public async Task A_trusted_statements_redirect_uri_is_the_one_registered()
    {
        await using var host = CreateStatementHost();
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var statement = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray(LegitRedirectUri),
            [RequestMembers.ClientUri] = "https://legit.example.com",
        });
        var metadata = StatementClientMetadata(AttackerRedirectUri);
        metadata[RequestMembers.SoftwareStatement] = statement;

        var registered = await RegisterClientAsync(client, discovery, metadata);

        Assert.Equal([LegitRedirectUri], RedirectUrisOf(registered));
        Assert.Equal("https://legit.example.com", registered[RequestMembers.ClientUri]!.GetValue<string>());
        Assert.Equal(statement, registered[RequestMembers.SoftwareStatement]!.GetValue<string>());

        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var read = await ReadJsonAsync(await client.SendAsync(
            Request(
                HttpMethod.Get,
                new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>()),
                registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>()),
            TestContext.Current.CancellationToken));
        Assert.Equal([LegitRedirectUri], RedirectUrisOf(read));
        Assert.Equal(statement, read[RequestMembers.SoftwareStatement]!.GetValue<string>());

        var refused = await AuthorizeAsync(client, discovery, clientId, AttackerRedirectUri);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Null(refused.Headers.Location);

        var answered = await AuthorizeAsync(client, discovery, clientId, LegitRedirectUri);
        Assert.True(
            answered.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"{(int)answered.StatusCode}: {await answered.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        Assert.Equal(LegitRedirectUri, answered.Headers.Location!.GetLeftPart(UriPartial.Path));
    }

    /// <summary>
    /// An RFC 7592 update naming another redirect URI leaves the one the registration's statement fixed: the update
    /// answers with it, and a read after it finds it alone, while a member the statement does not carry takes the
    /// update's value.
    /// </summary>
    [Fact]
    public async Task An_update_keeps_the_redirect_uri_the_statement_fixed()
    {
        await using var host = CreateStatementHost();
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = StatementClientMetadata(LegitRedirectUri);
        var statement = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray(LegitRedirectUri),
        });
        metadata[RequestMembers.SoftwareStatement] = statement;
        var registered = await RegisterClientAsync(client, discovery, metadata);
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var configurationUri = new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>());

        var replacement = StatementClientMetadata(AttackerRedirectUri);
        replacement[RequestMembers.ClientId] = clientId;
        replacement[RequestMembers.ClientName] = "renamed";
        var update = Request(
            HttpMethod.Put,
            configurationUri,
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        update.Content = JsonContent.Create(replacement);
        var updateResponse = await client.SendAsync(update, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        var updated = await ReadJsonAsync(updateResponse);

        Assert.Equal([LegitRedirectUri], RedirectUrisOf(updated));
        Assert.Equal("renamed", updated[RequestMembers.ClientName]!.GetValue<string>());
        Assert.Equal(statement, updated[RequestMembers.SoftwareStatement]!.GetValue<string>());

        var read = await ReadJsonAsync(await client.SendAsync(
            Request(HttpMethod.Get, configurationUri, updated[ResponseMembers.RegistrationAccessToken]!.GetValue<string>()),
            TestContext.Current.CancellationToken));
        Assert.Equal([LegitRedirectUri], RedirectUrisOf(read));

        var refused = await AuthorizeAsync(client, discovery, clientId, AttackerRedirectUri);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
    }

    /// <summary>
    /// RFC 7592 section 2.2 has an update carry back every field the read returned, the statement among them, so the
    /// statement the client registered with, sent back as it was returned, is the stored one rather than a new one to
    /// judge: the update is served once the statement's own validity has ended.
    /// </summary>
    [Fact]
    public async Task An_update_sending_back_the_registered_statement_is_served_after_it_expires()
    {
        var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
        await using var host = CreateStatementHost(configureServices: services =>
            services.Replace(ServiceDescriptor.Singleton<TimeProvider>(clock)));
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var statement = await TrustedStatementIssuer.IssueAsync(
            new JsonObject { [RequestMembers.RedirectUris] = new JsonArray(LegitRedirectUri) },
            expiresAt: clock.GetUtcNow().AddMinutes(10));
        var metadata = StatementClientMetadata(LegitRedirectUri);
        metadata[RequestMembers.SoftwareStatement] = statement;
        var registered = await RegisterClientAsync(client, discovery, metadata);

        clock.Advance(TimeSpan.FromDays(1));
        var replacement = StatementClientMetadata(LegitRedirectUri);
        replacement[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        replacement[RequestMembers.SoftwareStatement] = statement;
        var update = Request(
            HttpMethod.Put,
            new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>()),
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        update.Content = JsonContent.Create(replacement);
        var updateResponse = await client.SendAsync(update, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        Assert.Equal(statement, (await ReadJsonAsync(updateResponse))[RequestMembers.SoftwareStatement]!.GetValue<string>());
    }

    /// <summary>
    /// An empty <c>software_statement</c> presents no statement, so the client is registered without one: its read
    /// returns none and its update is served as any client's.
    /// </summary>
    [Fact]
    public async Task An_empty_statement_registers_a_client_without_one()
    {
        await using var host = CreateStatementHost();
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = StatementClientMetadata(LegitRedirectUri);
        metadata[RequestMembers.SoftwareStatement] = string.Empty;
        var registered = await RegisterClientAsync(client, discovery, metadata);
        var configurationUri = new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>());

        var replacement = StatementClientMetadata(AttackerRedirectUri);
        replacement[RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var update = Request(
            HttpMethod.Put,
            configurationUri,
            registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>());
        update.Content = JsonContent.Create(replacement);
        var updateResponse = await client.SendAsync(update, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, updateResponse.StatusCode);
        var updated = await ReadJsonAsync(updateResponse);
        Assert.Equal([AttackerRedirectUri], RedirectUrisOf(updated));
        Assert.Null(updated[RequestMembers.SoftwareStatement]);
    }

    /// <summary>
    /// The statement's values are judged as any registration's are: a statement naming a redirect URI a web client
    /// may not use is refused for it, though the body names one it may.
    /// </summary>
    [Fact]
    public async Task A_statements_redirect_uri_is_judged_as_the_registrations()
    {
        await using var host = CreateStatementHost();
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = StatementClientMetadata(LegitRedirectUri);
        metadata[RequestMembers.SoftwareStatement] = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray("http://legit.example.com/cb"),
        });

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// A server open to registration without an initial access token that requires a statement from a trusted issuer
    /// admits only what such an issuer vouches for: the stored client has the statement's redirect URI alone and is
    /// reviewed, so the server's own trust policy sends its authorization error to that address, while one naming the
    /// body's address is not redirected.
    /// </summary>
    [Fact]
    public async Task A_registration_requiring_a_trusted_statement_stores_a_reviewed_client_with_its_values()
    {
        await using var host = CreateStatementHost(requireStatement: true, services =>
            services.Replace(ServiceDescriptor.Singleton<IRedirectUriTrustPolicy, RedirectUriTrustPolicy>()));
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        Assert.False(host.Services.GetRequiredService<IOptions<OidcOptions>>().Value.RequireInitialAccessToken);
        var metadata = StatementClientMetadata(AttackerRedirectUri);
        metadata[RequestMembers.SoftwareStatement] = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray(LegitRedirectUri),
        });

        var registered = await RegisterClientAsync(client, discovery, metadata);
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();

        var stored = await FindStoredClientAsync(host, clientId);
        Assert.Equal([new Uri(LegitRedirectUri)], stored.RedirectUris);
        Assert.Equal(ClientTrust.Reviewed, stored.Trust);

        var toAttacker = await AuthorizeAsync(client, discovery, clientId, AttackerRedirectUri, UnsupportedChallengeMethod);
        Assert.Equal(HttpStatusCode.BadRequest, toAttacker.StatusCode);
        Assert.Null(toAttacker.Headers.Location);

        var toLegit = await AuthorizeAsync(client, discovery, clientId, LegitRedirectUri, UnsupportedChallengeMethod);
        Assert.StartsWith(LegitRedirectUri, toLegit.Headers.Location?.OriginalString);
    }

    /// <summary>
    /// Registration open to anybody holds a client to its defaults on the values it is registered with, a trusted
    /// statement's included: a statement adding a grant outside an interactive sign-in is refused as the body would be.
    /// </summary>
    [Fact]
    public async Task Under_open_registration_a_statement_adding_client_credentials_is_refused()
    {
        await using var host = CreateStatementHost(configureServices: WithoutHostSets);
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = ConfidentialStatementClientMetadata();
        metadata[RequestMembers.SoftwareStatement] = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials),
        });

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// A statement stating no resources leaves a client registered openly with none, though it sets the member: the
    /// stored client has the sign-in grant it registered with and may get an access token for no resource.
    /// </summary>
    [Fact]
    public async Task Under_open_registration_a_statement_naming_no_resource_leaves_the_client_with_none()
    {
        await using var host = CreateStatementHost(configureServices: WithoutHostSets);
        var client = CreateStatementClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = ConfidentialStatementClientMetadata();
        metadata[RequestMembers.SoftwareStatement] = await TrustedStatementIssuer.IssueAsync(new JsonObject
        {
            [RequestMembers.AllowedResources] = null,
        });

        var registered = await RegisterClientAsync(client, discovery, metadata);

        var stored = await FindStoredClientAsync(host, registered[ResponseMembers.ClientId]!.GetValue<string>());
        Assert.Equal([GrantTypes.AuthorizationCode], stored.EffectiveGrantTypes);
        Assert.Equal([], stored.AllowedResources!);
        Assert.Equal(ClientTrust.Unreviewed, stored.Trust);
    }

    /// <summary>
    /// The server's defaults for new clients in place of the grant types this suite's host names for them.
    /// </summary>
    private static void WithoutHostSets(IServiceCollection services)
        => services.PostConfigure<OidcOptions>(options => options.NewClientOptions =
            options.NewClientOptions with { AllowedGrantTypes = null, AllowedResources = null });

    /// <summary>
    /// A client authenticating with a secret, which may hold the client credentials grant, using the authorization
    /// code grant.
    /// </summary>
    private static JsonObject ConfidentialStatementClientMetadata()
    {
        var metadata = StatementClientMetadata(LegitRedirectUri);
        metadata[RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic;
        return metadata;
    }

    /// <summary>
    /// A code challenge method this server does not support, which RFC 7636 section 4.4.1 has answered with an
    /// authorization error at the client's redirect URI where the server may send it there.
    /// </summary>
    private const string UnsupportedChallengeMethod = "S384";

    private static async Task<ClientInfo> FindStoredClientAsync(WebApplicationFactory<Program> host, string clientId)
    {
        using var scope = host.Services.CreateScope();
        var found = await scope.ServiceProvider.GetRequiredService<IClientInfoProvider>()
            .FindClientAsync(TestTenant.Of(host.Services), clientId);
        return found.GetSuccess();
    }

    private WebApplicationFactory<Program> CreateStatementHost(
        bool requireStatement = false,
        Action<IServiceCollection>? configureServices = null)
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            TrustedStatementIssuer.TrustIn(services);
            services.PostConfigure<OidcOptions>(options =>
                options.SoftwareStatement.RequireSoftwareStatement = requireStatement);
            configureServices?.Invoke(services);
        }));

    private static HttpClient CreateStatementClient(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// A public client using the authorization code grant, registered at <paramref name="redirectUri"/>.
    /// </summary>
    private static JsonObject StatementClientMetadata(string redirectUri) => new()
    {
        [RequestMembers.ClientName] = "statement-client",
        [RequestMembers.RedirectUris] = new JsonArray(redirectUri),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };

    private static string[] RedirectUrisOf(JsonObject registration)
        => registration[ResponseMembers.RedirectUris]!.AsArray().Select(uri => uri!.GetValue<string>()).ToArray();

    private static Task<HttpResponseMessage> AuthorizeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string redirectUri,
        string codeChallengeMethod = CodeChallengeMethods.S256)
    {
        var parameters = CodeFlowParameters(clientId, GeneratePkcePair().Challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;
        parameters[AuthorizationRequest.Parameters.CodeChallengeMethod] = codeChallengeMethod;
        return client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
            TestContext.Current.CancellationToken);
    }
}
