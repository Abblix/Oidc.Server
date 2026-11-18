// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.NoneFlow;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

using RegistrationParameters = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// FAPI 2.0 Security Profile section 5.3.2.2 has the server require the response type code "for flows that use the
/// authorization endpoint". A tenant held to FAPI 2.0 starts with clients that never use it - a resource server that
/// only introspects tokens and a client of the client credentials grant, neither registering a response type - lets
/// the resource server introspect, and registers such a client, while it still refuses a registration for code
/// id_token, and its discovery document lists code as the one response type it supports.
/// </summary>
/// <remarks>
/// The host enables the implicit flow and the none response type, so code id_token and none are response types the
/// server supports and their absence at the FAPI 2.0 tenant is the profile's: the tenant holding its clients to no
/// profile registers the same request and lists them. The
/// clients the tenant starts with name PS256 for their ID tokens and authorization responses, since the startup check
/// holds every algorithm a client is configured for to FAPI 2.0 section 5.4.1 whether or not anything is issued under
/// it.
/// </remarks>
public sealed class Fapi2ClientsOutsideTheAuthorizationEndpointTests : IAsyncLifetime
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string ResourceServerId = "resource-server";
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "Canonical test redirect_uri a registration names; not a deployment URL.")]
    private const string RedirectUri = "https://client.example.com/callback";

    private static readonly RsaJsonWebKey ClientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly TenantDefinition FapiTenant = new()
    {
        Id = "acme",
        Issuer = new Uri(Host + Acme),
        DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
        Clients =
        [
            new ClientInfo(ResourceServerId)
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
                Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
                AllowedGrantTypes = [],
                AllowedResponseTypes = [],
                IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
                AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            },
            new ClientInfo("machine")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
                Jwks = new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)]),
                AllowedGrantTypes = [GrantTypes.ClientCredentials],
                AllowedResponseTypes = [],
                IdentityTokenSignedResponseAlgorithm = SigningAlgorithms.PS256,
                AuthorizationSignedResponseAlgorithm = SigningAlgorithms.PS256,
            },
        ],
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private static readonly TenantDefinition PlainTenant = new()
    {
        Id = "globex",
        Issuer = new Uri(Host + Globex),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
    };

    private WebApplication? _app;
    private HttpClient? _http;

    public async ValueTask InitializeAsync()
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddDynamicClientRegistration();
        builder.Services.AddIntrospection();
        builder.Services.EnableImplicitFlow();
        builder.Services.EnableNoneFlow();
        // FAPI 2.0 section 5.4.1 holds the tokens the server signs for itself to PS256, ES256 or EdDSA too
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.RegisterClient | OidcEndpoints.Introspection;
            options.RequireInitialAccessToken = false;
            options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = SigningAlgorithms.PS256;
        });
        builder.Services.Configure<OidcOptions>(options =>
        {
            options.Tenants.Add(FapiTenant);
            options.Tenants.Add(PlainTenant);
        });

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
        _app.UseAuthorization();
        _app.MapOidcEndpoints();
        await _app.StartAsync(TestContext.Current.CancellationToken);

        _http = _app.GetTestClient();
        _http.BaseAddress = new Uri(Host);
    }

    public async ValueTask DisposeAsync()
    {
        _http?.Dispose();
        if (_app is not null)
            await _app.DisposeAsync();
    }

    /// <summary>
    /// The resource server the tenant started with authenticates at introspection with a private key JWT, which is
    /// what it registered no response type for: a token the server never issued is answered inactive rather than the
    /// caller refused.
    /// </summary>
    [Fact]
    public async Task TheResourceServer_Introspects()
    {
        var now = TimeProvider.System.GetUtcNow();
        var assertion = await _app!.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.PS256, KeyId = ClientKey.KeyId },
                Payload =
                {
                    Issuer = ResourceServerId,
                    Subject = ResourceServerId,
                    Audiences = [Host + Acme],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(1),
                },
            },
            ClientKey);

        var response = await _http!.PostAsync(
            Acme + "/connect/introspect",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = "a-token-never-issued",
                [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
                [ClientRequest.Parameters.ClientAssertion] = assertion,
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.False(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.2.2 has the server "require the value of response_type described in
    /// [RFC6749] to be code", so the FAPI 2.0 tenant's discovery document lists code alone and not the implicit grant
    /// type a client registers for any other (RFC 7591 section 2.1), while the tenant holding its clients to no profile
    /// lists every response type the server makes up and the implicit grant type with them.
    /// </summary>
    [Fact]
    public async Task TheDiscoveryDocument_ListsTheResponseTypesTheTenantsProfileAdmits()
    {
        async Task<string[]> ListedAtAsync(string tenant, string parameter)
        {
            var document = JsonNode.Parse(await _http!.GetStringAsync(
                tenant + "/.well-known/openid-configuration", TestContext.Current.CancellationToken))!;
            return document[parameter]!.AsArray()
                .Select(value => value!.GetValue<string>())
                .ToArray();
        }

        Task<string[]> ResponseTypesListedAtAsync(string tenant)
            => ListedAtAsync(tenant, ConfigurationResponse.Parameters.ResponseTypesSupported);

        Assert.Equal([ResponseTypes.Code], await ResponseTypesListedAtAsync(Acme));
        Assert.Equal(
            [
                ResponseTypes.Code,
                ResponseTypes.Token,
                ResponseTypes.IdToken,
                ResponseTypes.None,
                $"{ResponseTypes.Code} {ResponseTypes.Token}",
                $"{ResponseTypes.Code} {ResponseTypes.IdToken}",
                $"{ResponseTypes.Token} {ResponseTypes.IdToken}",
                $"{ResponseTypes.Code} {ResponseTypes.Token} {ResponseTypes.IdToken}",
            ],
            await ResponseTypesListedAtAsync(Globex));

        var grantTypesAtAcme = await ListedAtAsync(Acme, ConfigurationResponse.Parameters.GrantTypesSupported);
        Assert.Contains(GrantTypes.AuthorizationCode, grantTypesAtAcme);
        Assert.DoesNotContain(GrantTypes.Implicit, grantTypesAtAcme);
        Assert.Contains(
            GrantTypes.Implicit,
            await ListedAtAsync(Globex, ConfigurationResponse.Parameters.GrantTypesSupported));
    }

    /// <summary>
    /// A registration for the client credentials grant alone, with the empty response_types RFC 7591 section 2.1
    /// correlates with it, is registered at the FAPI 2.0 tenant; one for code id_token is refused there with
    /// invalid_client_metadata and registered at the tenant holding its clients to no profile.
    /// </summary>
    [Theory]
    [InlineData(Acme, false, HttpStatusCode.Created)]
    [InlineData(Acme, true, HttpStatusCode.BadRequest)]
    [InlineData(Globex, true, HttpStatusCode.Created)]
    public async Task ARegistration_IsHeldToCodeOnlyWhereItUsesTheAuthorizationEndpoint(
        string tenant, bool hybrid, HttpStatusCode expected)
    {
        var registration = new JsonObject
        {
            [RegistrationParameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.PrivateKeyJwt,
            [RegistrationParameters.Jwks] = JsonSerializer.SerializeToNode(
                new JsonWebKeySet([ClientKey.Sanitize(includePrivateKeys: false)])),
        };

        if (hybrid)
        {
            registration[RegistrationParameters.RedirectUris] = new JsonArray { RedirectUri };
            registration[RegistrationParameters.ResponseTypes] =
                new JsonArray { $"{ResponseTypes.Code} {ResponseTypes.IdToken}" };
            registration[RegistrationParameters.GrantTypes] =
                new JsonArray { GrantTypes.AuthorizationCode, GrantTypes.Implicit };
        }
        else
        {
            registration[RegistrationParameters.ResponseTypes] = new JsonArray();
            registration[RegistrationParameters.GrantTypes] = new JsonArray { GrantTypes.ClientCredentials };
        }

        var response = await _http!.PostAsync(
            tenant + "/connect/register",
            new StringContent(registration.ToJsonString(), Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        if (expected == HttpStatusCode.BadRequest)
        {
            Assert.Equal(ErrorCodes.InvalidClientMetadata, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
            return;
        }

        if (!hybrid)
            Assert.Empty(body[RegistrationParameters.ResponseTypes]!.AsArray());
    }
}
