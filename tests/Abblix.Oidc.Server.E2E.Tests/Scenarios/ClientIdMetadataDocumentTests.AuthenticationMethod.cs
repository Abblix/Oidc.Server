// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Tests.Shared;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    private const string PublicSigningKeys =
        """{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"sig","kid":"1"}]}""";

    /// <summary>
    /// Section 5 has the server "select one of the values ... that it supports", and a tenant listing no certificate
    /// authority serves no client with tls_client_auth: the first declared method the tenant resolving the client admits
    /// is chosen, tls_client_auth where the tenant lists an authority, the private key JWT declared after it where it
    /// lists none.
    /// </summary>
    [Theory]
    [InlineData(new[] { ClientAuthenticationMethods.TlsClientAuth, ClientAuthenticationMethods.PrivateKeyJwt }, true,
        ClientAuthenticationMethods.TlsClientAuth)]
    [InlineData(new[] { ClientAuthenticationMethods.TlsClientAuth, ClientAuthenticationMethods.PrivateKeyJwt }, false,
        ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(new[] { ClientAuthenticationMethods.PrivateKeyJwt }, false, ClientAuthenticationMethods.PrivateKeyJwt)]
    public async Task TheClient_AuthenticatesWithTheFirstDeclaredMethodTheTenantAdmits(
        string[] declared,
        bool listsAuthority,
        string chosen)
    {
        using var authority = TestCertificateAuthority.Create();
        Serve(DocumentDeclaring(declared));
        await using var host = CreateHost();

        var client = await FindAsync(host, TenantListing("acme", listsAuthority ? authority : null));

        Assert.True(client.TryGetSuccess(out var found), client.ToString());
        Assert.Equal(chosen, found.TokenEndpointAuthMethod);
    }

    /// <summary>
    /// A client declaring tls_client_auth and then none is held to none at a tenant listing no certificate authority,
    /// and so goes without the grants kept for a client that authenticates itself.
    /// </summary>
    [Fact]
    public async Task AClientLeftWithNone_GoesWithoutTheGrantsOfAClientAuthenticatingItself()
    {
        var document = DocumentDeclaring([ClientAuthenticationMethods.TlsClientAuth, ClientAuthenticationMethods.None]);
        document[RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials);
        Serve(document);
        await using var host = CreateHost(options => options.ClientIdMetadataDocuments.AllowedGrantTypes =
            [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials]);

        var client = await FindAsync(host, TenantListing("acme", authority: null));

        Assert.True(client.TryGetSuccess(out var found), client.ToString());
        Assert.Equal(ClientAuthenticationMethods.None, found.TokenEndpointAuthMethod);
        Assert.DoesNotContain(GrantTypes.ClientCredentials, found.EffectiveGrantTypes);
    }

    /// <summary>
    /// One document, fetched once, serves each tenant by what that tenant admits: a tenant admitting none of the
    /// declared methods refuses the client, and the document is still held for a tenant admitting one.
    /// </summary>
    [Fact]
    public async Task ATenantAdmittingNoneOfTheMethods_RefusesTheClient_WhileAnotherServesIt()
    {
        using var authority = TestCertificateAuthority.Create();
        Serve(DocumentDeclaring([ClientAuthenticationMethods.TlsClientAuth]));
        await using var host = CreateHost();

        var refused = await FindAsync(host, TenantListing("plain", authority: null));
        var served = await FindAsync(host, TenantListing("acme", authority));

        Assert.False(refused.TryGetSuccess(out _));
        Assert.True(served.TryGetSuccess(out var found), served.ToString());
        Assert.Equal(ClientAuthenticationMethods.TlsClientAuth, found.TokenEndpointAuthMethod);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// A tenant held to FAPI 2.0, which refuses a public client (FAPI 2.0 Security Profile section 5.3.2.1), holds a
    /// document declaring none and the private key JWT to the latter, and refuses one declaring none alone.
    /// </summary>
    [Theory]
    [InlineData(new[] { ClientAuthenticationMethods.None, ClientAuthenticationMethods.PrivateKeyJwt },
        ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(new[] { ClientAuthenticationMethods.None }, null)]
    public async Task AFapiTenant_HoldsTheClientToAMethodItAdmits_OrRefusesIt(string[] declared, string? chosen)
    {
        Serve(DocumentDeclaring(declared));
        await using var host = CreateHost();
        var tenant = TenantListing("fapi", authority: null, ClientSecurityProfile.Fapi2);

        var client = await FindAsync(host, tenant);

        if (chosen is null)
        {
            Assert.False(client.TryGetSuccess(out _));
            return;
        }

        Assert.True(client.TryGetSuccess(out var found), client.ToString());
        Assert.Equal(chosen, found.TokenEndpointAuthMethod);
    }

    private static JsonObject DocumentDeclaring(string[] methods)
    {
        var document = PublicClientDocument();
        document.Remove(RegistrationMembers.TokenEndpointAuthMethod);
        document[RegistrationMembers.TokenEndpointAuthMethodsSupported] = new JsonArray([..methods.Select(m => JsonValue.Create(m))]);
        document[RegistrationMembers.TlsClientAuthSubjectDn] = "CN=client";
        document[RegistrationMembers.Jwks] = JsonNode.Parse(PublicSigningKeys);
        return document;
    }

    private static TenantDefinition TenantListing(
        string id,
        TestCertificateAuthority? authority,
        ClientSecurityProfile profile = ClientSecurityProfile.None) => new()
    {
        DefaultSecurityProfile = profile,
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        Id = id,
        Issuer = new Uri($"https://{id}.example.com"),
        TlsClientAuthCertificateAuthorities = authority is null ? [] : [authority.RootEncoded],
    };

    private static async Task<Abblix.Utils.Result<ClientInfo, ClientAbsence>> FindAsync(
        WebApplicationFactory<Program> host,
        TenantDefinition tenant)
    {
        using var scope = host.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IClientInfoProvider>().FindClientAsync(tenant, ClientId);
    }
}
