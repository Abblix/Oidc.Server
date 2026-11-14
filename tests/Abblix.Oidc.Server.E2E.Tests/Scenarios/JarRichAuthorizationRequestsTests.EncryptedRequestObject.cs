// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ConfigurationMembers = Abblix.Oidc.Server.Model.ConfigurationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// A request object encrypted to the server (RFC 9101 section 6.1) can be encrypted only under an algorithm one of
/// the tenant's own published encryption keys opens, and the discovery document lists exactly those, so what it
/// promises a client is what the server accepts.
/// </remarks>
public partial class JarRichAuthorizationRequestsTests
{
    /// <summary>
    /// A tenant whose only encryption key declares RSA-OAEP-256 lists that algorithm alone, accepts a request object
    /// encrypted under it, and refuses one encrypted to the same key under RSA-OAEP, which the document does not list.
    /// </summary>
    [Fact]
    public async Task EncryptedRequestObject_IsAcceptedUnderTheListedAlgorithmOnly()
    {
        var serverKey = JsonWebKeyFactory.CreateRsa(
            PublicKeyUsages.Encryption,
            EncryptionAlgorithms.KeyManagement.RsaOaep256);
        await using var host = CreateHostWithEncryptionKeys(serverKey);
        var client = CreateClientFor(host);

        var document = await FetchDiscoveryJsonAsync(client);
        Assert.Equal(
            [EncryptionAlgorithms.KeyManagement.RsaOaep256],
            StringsOf(document, ConfigurationMembers.RequestObjectEncryptionAlgValuesSupported));
        Assert.NotEmpty(StringsOf(document, ConfigurationMembers.RequestObjectEncryptionEncValuesSupported));

        var discovery = await FetchDiscoveryAsync(client);
        var signing = await RegisterSigningClientAsync(client, discovery);
        var publicKey = serverKey.Sanitize(includePrivateKeys: false);

        var accepted = await PushEncryptedAsync(
            client, discovery, signing, publicKey, EncryptionAlgorithms.KeyManagement.RsaOaep256);
        Assert.True(accepted.StatusCode == HttpStatusCode.Created, await DescribeAsync(accepted));

        // The client encrypts to the same public key under an algorithm the key does not declare
        var refused = await PushEncryptedAsync(
            client, discovery, signing, publicKey with { Algorithm = null }, EncryptionAlgorithms.KeyManagement.RsaOaep);
        Assert.True(refused.StatusCode == HttpStatusCode.BadRequest, await DescribeAsync(refused));
        var error = JsonNode.Parse(await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequestObject, error[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A tenant whose RSA encryption key declares no algorithm lists the RSA key management algorithms its material
    /// performs that the host registers - RSA1_5 is opt-in and left out - and no algorithm of another key type.
    /// </summary>
    [Fact]
    public async Task Discovery_ListsTheRsaAlgorithms_ForAnRsaKeyDeclaringNone()
    {
        await using var host = CreateHostWithEncryptionKeys(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption));
        var client = CreateClientFor(host);

        var document = await FetchDiscoveryJsonAsync(client);

        Assert.Equal(
            [
                EncryptionAlgorithms.KeyManagement.RsaOaep,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
            ],
            StringsOf(document, ConfigurationMembers.RequestObjectEncryptionAlgValuesSupported).Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// The shared host configures no encryption key, so no client could encrypt a request object to it: both
    /// members are omitted, as OpenID Connect Discovery 1.0 section 4.2 requires of a claim with zero elements.
    /// </summary>
    [Fact]
    public async Task Discovery_OmitsRequestObjectEncryption_WithoutAnEncryptionKey()
    {
        var document = await FetchDiscoveryJsonAsync(CreateClient());

        // The control: the document is read and request objects are accepted, so an absent member means omitted
        Assert.True(document.TryGetProperty(ConfigurationMembers.RequestObjectSigningAlgValuesSupported, out _));
        Assert.False(document.TryGetProperty(ConfigurationMembers.RequestObjectEncryptionAlgValuesSupported, out _));
        Assert.False(document.TryGetProperty(ConfigurationMembers.RequestObjectEncryptionEncValuesSupported, out _));
    }

    private WebApplicationFactory<Program> CreateHostWithEncryptionKeys(params JsonWebKey[] keys)
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<TestTenantSettings>(tenant => tenant.EncryptionKeys = keys)));

    private static async Task<JsonElement> FetchDiscoveryJsonAsync(HttpClient client)
    {
        var json = await client.GetStringAsync(
            "/.well-known/openid-configuration",
            TestContext.Current.CancellationToken);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static string[] StringsOf(JsonElement document, string member)
        => document.GetProperty(member).EnumerateArray().Select(item => item.GetString()!).ToArray();

    /// <summary>
    /// Pushes a code flow request whose request object is signed with the client's key and then encrypted to
    /// <paramref name="serverKey"/> under <paramref name="keyManagementAlgorithm"/>.
    /// </summary>
    private static async Task<HttpResponseMessage> PushEncryptedAsync(
        HttpClient client,
        Model.DiscoveryDocument discovery,
        SigningClient signing,
        JsonWebKey serverKey,
        string keyManagementAlgorithm)
    {
        var signed = await SignRequestObjectAsync(discovery, signing, GeneratePkcePair().Challenge);
        var encrypted = await JwtServices.GetRequiredService<IJsonWebTokenEncryptor>().EncryptAsync(
            Encoding.UTF8.GetBytes(signed),
            serverKey,
            tokenType: null,
            contentType: JsonWebTokenTypes.Jwt,
            keyManagementAlgorithm,
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            TestContext.Current.CancellationToken);

        return await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = signing.ClientId,
            [ClientRequest.Parameters.ClientSecret] = signing.ClientSecret,
            [AuthorizationRequest.Parameters.Request] = encrypted,
        });
    }

    private static async Task<string> DescribeAsync(HttpResponseMessage response)
        => $"{(int)response.StatusCode}: "
           + await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
}
