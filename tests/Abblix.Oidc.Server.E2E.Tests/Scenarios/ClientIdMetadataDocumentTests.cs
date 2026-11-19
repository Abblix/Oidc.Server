// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Tests.Shared;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client identifying itself by the URL of its own metadata document (draft-ietf-oauth-client-id-metadata-document),
/// on a host that turned the feature on, as it meets the discovery, authorization, token and registration endpoints.
/// </summary>
public class ClientIdMetadataDocumentTests(TestFactory factory) : TestBase(factory)
{
    private const string ClientId = "https://client.example.com/oauth/metadata.json";

    private readonly MetadataDocumentOrigin _origin = new();

    private WebApplicationFactory<Program> CreateHost(
        Action<OidcOptions>? configure = null,
        Action<IServiceCollection>? configureServices = null)
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            configureServices?.Invoke(services);
            new Registered(services).AddClientIdMetadataDocuments();

            // The client's own web server, standing behind the published transport in place of the network
            services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => _origin);

            if (configure is not null)
                services.PostConfigure(configure);
        }));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static JsonObject PublicClientDocument() => new()
    {
        [RegistrationMembers.ClientId] = ClientId,
        [RegistrationMembers.ClientName] = "Metadata Document Client",
        [RegistrationMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
        [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
        [RegistrationMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.None,
    };

    private void Serve(JsonObject document) => _origin.Serve(ClientId, document.ToJsonString());

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task TheDiscoveryDocument_AdvertisesTheFeature_OnlyWhereTheHostTurnedItOn(string path)
    {
        await using var host = CreateHost();

        var on = JsonNode.Parse(await CreateClientFor(host).GetStringAsync(path, TestContext.Current.CancellationToken))!;
        var off = JsonNode.Parse(await CreateClient().GetStringAsync(path, TestContext.Current.CancellationToken))!;

        Assert.True(on[ConfigurationResponse.Parameters.ClientIdMetadataDocumentSupported]!.GetValue<bool>());
        Assert.False(off.AsObject().ContainsKey(ConfigurationResponse.Parameters.ClientIdMetadataDocumentSupported));
    }

    /// <summary>
    /// The whole flow of a public client: the server fetches the document the first time the client is named, holds
    /// it, and issues tokens to the client by its URL.
    /// </summary>
    [Fact]
    public async Task APublicClient_IsIssuedTokensUnderItsUrl_WithOneFetchOfItsDocument()
    {
        Serve(PublicClientDocument());
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, CodeExchange(code, verifier));

        var accessToken = DecodeJwtPayload(tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(ClientId, accessToken[IanaClaimTypes.ClientId]!.GetValue<string>());
        Assert.Equal(1, _origin.RequestsTo(ClientId));
        Assert.Contains(
            _origin.Requests,
            request => request.Headers.Accept.Contains(new MediaTypeWithQualityHeaderValue("application/json")));
    }

    /// <summary>
    /// Section 4.2: the server "MUST ensure that the redirect URL in an authorization request is an exact match ... of
    /// a registered redirect URL", and the document is what registers them.
    /// </summary>
    [Fact]
    public async Task ARedirectUriTheDocumentDoesNotList_IsRefused()
    {
        Serve(PublicClientDocument());
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = "https://client.example.com/other";

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    /// <summary>
    /// Section 6.1: when the document "could not be retrieved or was invalid, the authorization server MUST NOT redirect
    /// the user agent to the client", and sections 5 and 6 abort the authorization request "with invalid_client".
    /// </summary>
    [Theory]
    [InlineData(Unavailable.NotFound)]
    [InlineData(Unavailable.AnotherClientId)]
    [InlineData(Unavailable.SharedSecret)]
    [InlineData(Unavailable.NotAllowed)]
    public async Task AClientWhoseDocumentIsRefused_IsAnInvalidClient_WithoutARedirect(Unavailable why)
    {
        var (allowedPrefixes, fetched) = Arrange(why);
        await using var host = CreateHost(allowedPrefixes is null
            ? null
            : options => options.ClientIdMetadataDocuments.AllowedClientIdPrefixes = allowedPrefixes);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, CodeFlowParameters(ClientId, GeneratePkcePair().Challenge)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
        // A refusal is not held (section 6.2: the server "MUST NOT cache error responses"), so each lookup of the
        // client within the request asks again; one refused before any fetch reaches nothing
        Assert.Equal(fetched, _origin.RequestsTo(ClientId) > 0);
    }

    /// <summary>
    /// Serves the document <paramref name="why"/> names, and says which prefixes the host allows and whether the
    /// refusal takes a fetch.
    /// </summary>
    private (string[]? AllowedPrefixes, bool Fetched) Arrange(Unavailable why)
    {
        var document = PublicClientDocument();
        switch (why)
        {
            case Unavailable.NotFound:
                return (null, true);

            case Unavailable.AnotherClientId:
                document[RegistrationMembers.ClientId] = "https://client.example.com/oauth/other.json";
                Serve(document);
                return (null, true);

            case Unavailable.SharedSecret:
                document[RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic;
                Serve(document);
                return (null, true);

            case Unavailable.NotAllowed:
                Serve(document);
                return (["https://trusted.example.com/"], false);

            default:
                throw new ArgumentOutOfRangeException(nameof(why), why, null);
        }
    }

    public enum Unavailable
    {
        NotFound,
        AnotherClientId,
        SharedSecret,
        NotAllowed,
    }

    /// <summary>
    /// Section 10.7 names "a URI scheme such as javascript:" among those a server parses at its peril: a document with
    /// such a redirect URI would have the server post its answer, an error to a request without a session included,
    /// into script running in its own origin.
    /// </summary>
    [Fact]
    public async Task ADocumentRedirectingToScript_IsAnInvalidClient_AndNoFormIsRendered()
    {
        const string script = "javascript:alert(document.domain)//x";
        var document = PublicClientDocument();
        document[RegistrationMembers.RedirectUris] = new JsonArray(script);
        Serve(document);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters[AuthorizationRequest.Parameters.RedirectUri] = script;
        parameters[AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.FormPost;
        parameters[AuthorizationRequest.Parameters.Prompt] = Prompts.None;

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// A document is held to the host's limits on a new client as a registration is: the offline access it states
    /// may be at most what <see cref="NewClientOptions.OfflineAccess"/> grants.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheOfflineAccessADocumentStates_IsHeldToTheHostsLimit(bool granted)
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.OfflineAccess] = "allowed";
        Serve(document);
        await using var host = CreateHost(granted
            ? options => options.NewClientOptions = options.NewClientOptions with { OfflineAccess = OfflineAccess.Allowed }
            : null);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, CodeFlowParameters(ClientId, GeneratePkcePair().Challenge)),
            TestContext.Current.CancellationToken);

        Assert.Equal(granted, response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther);
    }

    /// <summary>
    /// RFC 9700 section 2.1.1: "Public clients MUST use PKCE", so a document cannot turn it off.
    /// </summary>
    [Fact]
    public async Task ADocumentTurningPkceOff_StillHasToUseIt()
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.PkceRequired] = false;
        Serve(document);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var parameters = CodeFlowParameters(ClientId, GeneratePkcePair().Challenge);
        parameters.Remove(AuthorizationRequest.Parameters.CodeChallenge);
        parameters.Remove(AuthorizationRequest.Parameters.CodeChallengeMethod);

        Assert.Equal(ErrorCodes.InvalidRequest, await AuthorizeAndExtractErrorAsync(client, discovery, parameters));
    }

    /// <summary>
    /// RFC 6749 section 4.4: "The client credentials grant type MUST only be used by confidential clients". A document
    /// is anybody's, so one naming no authentication method gets no token for itself, whatever grant it declares.
    /// </summary>
    [Fact]
    public async Task ADocumentAskingForClientCredentials_GetsNoToken()
    {
        var document = PublicClientDocument();
        document[RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials);
        document[RegistrationMembers.ResponseTypes] = new JsonArray();
        document.Remove(RegistrationMembers.RedirectUris);
        Serve(document);
        await using var host = CreateHost(options => options.ClientIdMetadataDocuments.AllowedGrantTypes =
            [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials]);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientId] = ClientId,
            [TokenRequest.Parameters.Scope] = TestConstants.ApiScope,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// Section 6.1: "At the token endpoint ... the authorization server MUST return an invalid_client error".
    /// </summary>
    [Fact]
    public async Task AClientWithoutADocument_IsAnInvalidClientAtTheTokenEndpoint()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, CodeExchange("code", GeneratePkcePair().Verifier));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// Section 5: "If the authorization server has determined the client's token endpoint authentication method to be
    /// none, and the client includes client authentication in a token request, the authorization server MUST reject
    /// the request with invalid_client".
    /// </summary>
    [Fact]
    public async Task APublicClientPresentingASecret_IsAnInvalidClient()
    {
        Serve(PublicClientDocument());
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(CodeExchange(code, verifier)),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(ClientId)}:secret")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// Section 5: a client declaring private_key_jwt at a server supporting it is held to it, "using a corresponding key
    /// discovered from the client's metadata document".
    /// </summary>
    [Fact]
    public async Task AClientDeclaringPrivateKeyJwt_AuthenticatesWithTheKeyItsDocumentPublishes()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var document = PublicClientDocument();
        document.Remove(RegistrationMembers.TokenEndpointAuthMethod);
        document[RegistrationMembers.TokenEndpointAuthMethodsSupported] =
            new JsonArray(ClientAuthenticationMethods.None, ClientAuthenticationMethods.PrivateKeyJwt);
        document[RegistrationMembers.Jwks] = JsonSerializer.SerializeToNode(
            new JsonWebKeySet([key.Sanitize(includePrivateKeys: false)]));
        Serve(document);

        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));

        // Without the assertion the client is refused, since it is no longer a public one
        using var unauthenticated = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, CodeExchange(code, verifier));
        Assert.Equal(ErrorCodes.InvalidClient, await ErrorResponseReader.ErrorCodeOf(unauthenticated));

        var code2 = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));
        var form = CodeExchange(code2, verifier);
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, form);
        Assert.NotNull(tokens[TokenResponse.Parameters.AccessToken]);
    }

    /// <summary>
    /// Section 10.7: the server "MUST NOT fetch ... any URLs contained within a Client ID Metadata Document that resolve
    /// to special-use IP addresses as defined in [RFC6890]". A key set whose host answers with the NAT64 prefix is not
    /// fetched for a document client, though it carries a public address, while one answering with a public address is.
    /// </summary>
    [Theory]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("64:ff9b::808:808", false)]
    public async Task ADocumentsKeySet_IsFetchedOnlyFromAnAddressNoSpecialPurposeBlockHolds(string resolved, bool authenticated)
    {
        const string jwksUri = "https://keys.client.example.com/jwks.json";
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var document = PublicClientDocument();
        document[RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt;
        document[RegistrationMembers.JwksUri] = jwksUri;
        Serve(document);
        _origin.Serve(jwksUri, JsonSerializer.Serialize(new JsonWebKeySet([key.Sanitize(includePrivateKeys: false)])));

        // The server's own SSRF validation over the key set fetch, with the name answering as the row says
        await using var host = CreateHost(configureServices: services => services
            .AddHttpClient(SecureFetchTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
            {
                var guard = new SsrfValidatingHttpMessageHandler(
                    serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>(),
                    serviceProvider.GetRequiredService<ISecureUriValidator>(),
                    (_, _) => Task.FromResult(new[] { IPAddress.Parse(resolved) }));
                guard.InnerHandler!.Dispose();
                guard.InnerHandler = _origin;
                return guard;
            }));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));
        var form = CodeExchange(code, verifier);
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);

        Assert.Equal(authenticated, response.IsSuccessStatusCode);
        Assert.Equal(authenticated, _origin.RequestsTo(jwksUri) > 0);
    }

    /// <summary>
    /// Section 9.1: a server issuing client identifiers of its own beside documents "SHOULD ensure that the client_id
    /// strings it generates do not start with https://", so a registrant cannot take a document's URL.
    /// </summary>
    [Fact]
    public async Task ARegistrationNamingAClientIdentifierUrl_IsRefused()
    {
        Serve(PublicClientDocument());
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var metadata = PublicClientDocument();
        metadata[RegistrationMembers.RedirectUris] = new JsonArray("https://attacker.example.com/cb");

        using var response = await client.PostAsync(
            discovery.RegistrationEndpoint,
            new StringContent(metadata.ToJsonString(), Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, await ErrorResponseReader.ErrorCodeOf(response));
        Assert.Equal(0, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A client store the host registers after the feature replaces the store that resolves documents, while discovery
    /// would still advertise them, so the host does not start.
    /// </summary>
    [Fact]
    public async Task AClientStoreRegisteredAfterTheFeature_StopsTheHostFromStarting()
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            new Registered(services).AddClientIdMetadataDocuments();
            services.AddSingleton<IClientInfoProvider, NoClients>();
        }));

        Assert.ThrowsAny<OptionsValidationException>(() => host.CreateClient());
    }

    /// <summary>
    /// A host's own client store, holding no client.
    /// </summary>
    private sealed class NoClients : IClientInfoProvider
    {
        public Task<ClientInfo?> TryFindClientAsync(TenantDefinition tenant, string clientId)
            => Task.FromResult<ClientInfo?>(null);
    }

    private static Dictionary<string, string> CodeExchange(string code, string verifier) => new()
    {
        [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
        [TokenRequest.Parameters.Code] = code,
        [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
        [TokenRequest.Parameters.CodeVerifier] = verifier,
        [ClientRequest.Parameters.ClientId] = ClientId,
    };

    /// <summary>
    /// The server's registration as a host holds it, for a test registering its features after the host's own.
    /// </summary>
    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
