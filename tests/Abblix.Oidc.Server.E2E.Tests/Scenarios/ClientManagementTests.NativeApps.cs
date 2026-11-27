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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

// RFC 8252, OAuth 2.0 for Native Apps, as a native app meets the registration, authorization and token endpoints
public partial class ClientManagementTests
{
    private const string PrivateUseRedirectUri = "com.example.app:/oauth2redirect";
    private const string RegisteredLoopbackRedirectUri = "http://127.0.0.1:4000/oauth2redirect";
    private const string RegisteredLocalhostRedirectUri = "http://localhost/oauth2redirect";
    private const string ClaimedHttpsRedirectUri = "https://app.example.com/oauth2redirect";

    /// <summary>
    /// RFC 8252 section 8.4: "At a minimum, any private-use URI scheme that doesn't contain a period character (".")
    /// SHOULD be rejected." The javascript and data schemes carry none, and a response posted to either would run in
    /// this server's origin, so a native client registering one is refused, on registration and on an update.
    /// </summary>
    [Theory]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("javascript:alert(1)", true)]
    [InlineData("data:text/html,callback", false)]
    [InlineData("myapp:/oauth2redirect", false)]
    [InlineData("myapp:/oauth2redirect", true)]
    public async Task A_native_client_registering_a_scheme_without_a_period_is_refused(string redirectUri, bool onUpdate)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = NativeClientMetadata("native-scheme-without-period", redirectUri);

        var response = await RegisterOrUpdateAsync(client, discovery, metadata, onUpdate, "native-scheme-without-period");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// The same rule for the URI the user agent is sent to after logout.
    /// </summary>
    [Fact]
    public async Task A_native_client_registering_a_script_post_logout_redirect_uri_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = NativeClientMetadata("native-script-post-logout", PrivateUseRedirectUri);
        metadata[RequestMembers.PostLogoutRedirectUris] = new JsonArray("javascript:alert(1)");

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint!, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// A web client is held to https (OpenID Connect Dynamic Client Registration 1.0 section 2), so neither a script
    /// scheme nor a private-use one reaches it.
    /// </summary>
    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData(PrivateUseRedirectUri)]
    public async Task A_web_client_registering_a_scheme_other_than_https_is_refused(string redirectUri)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = NativeClientMetadata("web-non-https", redirectUri);
        metadata[RequestMembers.ApplicationType] = ApplicationTypes.Web;

        var response = await client.PostAsJsonAsync(
            discovery.RegistrationEndpoint!, metadata, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRedirectUri, (await ReadJsonAsync(response))[ErrorMember]!.GetValue<string>());
    }

    /// <summary>
    /// RFC 8252 section 8.1: "Authorization servers SHOULD reject authorization requests from native apps that don't
    /// use PKCE", and this server holds a public client to the PKCE RFC 9700 section 2.1.1 has it use. The authorization
    /// endpoint holds a native or public client to PKCE whatever it states, so asking to go without it is refused on
    /// registration and on an update; a confidential web client may.
    /// </summary>
    [Theory]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.None, false, HttpStatusCode.BadRequest)]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.None, true, HttpStatusCode.BadRequest)]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.ClientSecretBasic, false, HttpStatusCode.BadRequest)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.None, false, HttpStatusCode.BadRequest)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.None, true, HttpStatusCode.BadRequest)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.ClientSecretBasic, false, HttpStatusCode.Created)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.ClientSecretBasic, true, HttpStatusCode.OK)]
    public async Task Only_a_confidential_web_client_registers_without_pkce(
        string applicationType, string authMethod, bool onUpdate, HttpStatusCode expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = NativeClientMetadata(
            "without-pkce",
            applicationType == ApplicationTypes.Native ? PrivateUseRedirectUri : ClaimedHttpsRedirectUri);
        metadata[RequestMembers.ApplicationType] = applicationType;
        metadata[RequestMembers.TokenEndpointAuthMethod] = authMethod;
        metadata[RequestMembers.PkceRequired] = false;

        var response = await RegisterOrUpdateAsync(client, discovery, metadata, onUpdate, "without-pkce");

        var body = await ReadJsonAsync(response);
        Assert.True(response.StatusCode == expected, $"{(int)response.StatusCode}: {body[DescriptionMember]}");
        if (expected == HttpStatusCode.BadRequest)
            Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorMember]!.GetValue<string>());
        else
            Assert.False(body[RequestMembers.PkceRequired]!.GetValue<bool>());
    }

    /// <summary>
    /// RFC 8252 section 7: "authorization servers MUST offer at least the three redirect URI options described in the
    /// following subsections to native apps". The private-use scheme (section 7.1) and the loopback interface on the
    /// port the app listens on at the time of the request (section 7.3, "The authorization server MUST allow any port
    /// to be specified at the time of the request for loopback IP redirect URIs", and RFC 9700 section 4.1.3 the same for
    /// "a localhost URI") are registered as a native client;
    /// a claimed https URI (section 7.2), "indistinguishable to the authorization server from a regular web-based client
    /// redirect URI", as a web client without credentials, since OpenID Connect Dynamic Client Registration 1.0
    /// section 2 has native clients "only register redirect_uris using custom URI schemes or loopback URLs using the
    /// http scheme". Each one receives a code and redeems it.
    /// </summary>
    [Theory]
    [InlineData(ApplicationTypes.Native, PrivateUseRedirectUri)]
    [InlineData(ApplicationTypes.Native, "http://127.0.0.1:51004/oauth2redirect")]
    [InlineData(ApplicationTypes.Native, "http://localhost:53111/oauth2redirect")]
    [InlineData(ApplicationTypes.Web, ClaimedHttpsRedirectUri)]
    public async Task A_native_app_receives_a_code_at_its_redirect_uri_and_redeems_it(
        string applicationType, string redirectUri)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = NativeClientMetadata(
            "native-app",
            applicationType == ApplicationTypes.Native ? PrivateUseRedirectUri : ClaimedHttpsRedirectUri);
        metadata[RequestMembers.ApplicationType] = applicationType;
        if (applicationType == ApplicationTypes.Native)
        {
            metadata[RequestMembers.RedirectUris]!.AsArray().Add(RegisteredLoopbackRedirectUri);
            metadata[RequestMembers.RedirectUris]!.AsArray().Add(RegisteredLocalhostRedirectUri);
        }

        var registered = await RegisterClientAsync(client, discovery, metadata);
        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = redirectUri;

        var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
            TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"{(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        var location = response.Headers.Location!;
        Assert.Equal(redirectUri, location.GetLeftPart(UriPartial.Path));
        var code = System.Web.HttpUtility.ParseQueryString(location.Query)[ResponseParameters.Code];
        Assert.NotNull(code);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = redirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = clientId,
        });

        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
    }

    /// <summary>
    /// A host declaring a native client that authenticates with a shared secret does not start, since RFC 8252 section
    /// 8.5 has such a secret not accepted "as proof of the client's identity", and the refusal names the client; the
    /// same client declared public, with PKCE, starts and is served.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, false)]
    [InlineData(ClientAuthenticationMethods.None, true)]
    public async Task A_host_declaring_a_native_client_starts_only_when_the_client_is_public(
        string authMethod, bool starts)
    {
        const string clientId = "declared-native-app";
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<TestTenantSettings>(tenant => tenant.Clients =
                [
                    .. tenant.Clients,
                    new ClientInfo(clientId)
                    {
                        ApplicationType = ApplicationTypes.Native,
                        TokenEndpointAuthMethod = authMethod,
                        ClientSecrets = [new ClientSecret { Sha256Hash = new byte[32] }],
                        RedirectUris = [new Uri(PrivateUseRedirectUri)],
                    },
                ])));
        var createClient = () => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        if (!starts)
        {
            var exception = Assert.Throws<OptionsValidationException>(createClient);
            Assert.Contains(exception.Failures, failure => failure.Contains($"'{clientId}'"));
            return;
        }

        await FetchDiscoveryAsync(createClient());
    }

    /// <summary>
    /// The authorization endpoint holds a client the host declares to PKCE by its kind, whatever it states: a public
    /// web client with <see cref="ClientInfo.PkceRequired"/> false is refused a code without a code_challenge, and a
    /// confidential web client stating the same is served.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, false)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, true)]
    public async Task A_declared_client_turning_pkce_off_goes_without_it_only_when_confidential(
        string authMethod, bool served)
    {
        const string clientId = "declared-without-pkce";
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<TestTenantSettings>(tenant => tenant.Clients =
                [
                    .. tenant.Clients,
                    new ClientInfo(clientId)
                    {
                        TokenEndpointAuthMethod = authMethod,
                        ClientSecrets = [new ClientSecret { Sha256Hash = new byte[32] }],
                        RedirectUris = [new Uri(TestConstants.RedirectUri)],
                        PkceRequired = false,
                    },
                ])));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = CodeFlowParameters(clientId, GeneratePkcePair().Challenge);
        parameters.Remove(AuthorizationRequest.Parameters.CodeChallenge);
        parameters.Remove(AuthorizationRequest.Parameters.CodeChallengeMethod);

        var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
            TestContext.Current.CancellationToken);

        Assert.True(
            response.StatusCode is HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"{(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        var query = System.Web.HttpUtility.ParseQueryString(response.Headers.Location!.Query);
        if (served)
            Assert.NotNull(query[ResponseParameters.Code]);
        else
            Assert.Equal(ErrorCodes.InvalidRequest, query[ResponseParameters.Error]);
    }

    /// <summary>
    /// A public native client with one redirect URI and the authorization code grant.
    /// </summary>
    private static JsonObject NativeClientMetadata(string clientName, string redirectUri) => new()
    {
        [RequestMembers.ClientName] = clientName,
        [RequestMembers.ApplicationType] = ApplicationTypes.Native,
        [RequestMembers.RedirectUris] = new JsonArray(redirectUri),
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
        [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };
}
