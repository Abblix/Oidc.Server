// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using Azure;
using Azure.Identity;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Exercises <see cref="KeyVaultClient"/> against a stub transport and a fake credential, proving the
/// IHttpClientFactory seam drives the Azure SDK end to end: the injected <see cref="HttpMessageHandler"/> is the
/// transport for every Key Vault call, so RSA and EC signing, unwrapping and public-key fetch round-trip without a
/// live vault.
/// </summary>
public sealed class KeyVaultClientTests : IDisposable
{
    private static readonly Uri VaultUri = new("https://contoso.vault.azure.net/");

    // In production IHttpClientFactory owns the HttpClient and the custodian deliberately does not dispose it (a
    // typed client never owns the factory's handler), so the test owns that lifetime here, as the Vault suite does.
    private readonly List<HttpClient> _httpClients = [];

    private KeyVaultClient ClientOver(StubHttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        _httpClients.Add(httpClient);
        return new KeyVaultClient(
            NullLogger<KeyVaultClient>.Instance,
            new AzureKeyVaultOptions { KeyVaultUri = VaultUri },
            new StaticTokenCredential(),
            httpClient);
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    private static async Task<JsonWebKey> FirstPublicKeyAsync(IAsyncEnumerable<KeyVersion> versions)
    {
        await using var enumerator = versions.GetAsyncEnumerator();
        if (!await enumerator.MoveNextAsync())
            throw new InvalidOperationException("The custodian returned no key versions.");
        return enumerator.Current.PublicKey;
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsAnRsaKeyThroughTheInjectedTransport()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(VaultUri, "oidc-sign", ("v1", 1_700_000_000L)))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", expected)));

        var key = await FirstPublicKeyAsync(ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var rsaKey = Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal(expected.Modulus, rsaKey.Modulus);
        Assert.False(rsaKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsAnEcKeyThroughTheInjectedTransport()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(VaultUri, "oidc-sign", ("v1", 1_700_000_000L)))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.EcKeyBundle(VaultUri, "oidc-sign", ecdsa.ExportParameters(false))));

        var key = await FirstPublicKeyAsync(ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var ecKey = Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("P-256", ecKey.Curve);
        Assert.False(ecKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_PublishesEveryEnabledVersion_WithVersionedKidsAndCreationTimes()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var created1 = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000L);
        var created2 = DateTimeOffset.FromUnixTimeSeconds(1_710_000_000L);

        var handler = new StubHttpMessageHandler(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/versions", StringComparison.Ordinal))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(
                    VaultUri, "oidc-sign", ("v1", created1.ToUnixTimeSeconds()), ("v2", created2.ToUnixTimeSeconds())));

            // A per-version key fetch: the crypto material of the version the path names. The bundle's own kid is
            // ignored - the client stamps the kid from the key name and version.
            var parameters = path.EndsWith("/v1", StringComparison.Ordinal)
                ? rsa1.ExportParameters(false)
                : rsa2.ExportParameters(false);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", parameters));
        });

        var versions = new List<KeyVersion>();
        await foreach (var version in ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken))
            versions.Add(version);

        Assert.Equal(2, versions.Count);
        var first = versions.Single(version => version.PublicKey.KeyId == "oidc-sign/v1");
        var second = versions.Single(version => version.PublicKey.KeyId == "oidc-sign/v2");
        Assert.Equal(created1, first.CreatedAt);
        Assert.Equal(created2, second.CreatedAt);
        Assert.Equal(rsa1.ExportParameters(false).Modulus, Assert.IsType<RsaJsonWebKey>(first.PublicKey).Modulus);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_SkipsADisabledVersion()
    {
        // Disabling a version in Key Vault is how an operator takes a compromised key out of service. If this
        // client published it anyway, the key would stay in the JWKS and stay eligible to sign - the revocation
        // would appear to have been carried out while changing nothing.
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(
                    VaultUri,
                    "oidc-sign",
                    ("live", 1_700_000_000L, true),
                    ("revoked", 1_710_000_000L, false)))
                : StubHttpMessageHandler.Json(
                    HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", rsa.ExportParameters(false))));

        var versions = new List<KeyVersion>();
        await foreach (var version in ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken))
            versions.Add(version);

        Assert.Equal("oidc-sign/live", Assert.Single(versions).PublicKey.KeyId);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_FailsWhenAVersionHasNoCreationTime()
    {
        // The creation time decides which version signs and when a rotation takes over. A version whose age is
        // unknown cannot be ordered, so it has to stop the enumeration rather than be dated to year one and sort
        // as ancient - which would quietly make it ineligible to produce with and impossible to notice.
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(
                    VaultUri, "oidc-sign", ("undated", null, true)))
                : StubHttpMessageHandler.Json(
                    HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", rsa.ExportParameters(false))));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (var _ in ClientOver(handler).GetKeyVersionsAsync(
                               "oidc-sign", TestContext.Current.CancellationToken))
            {
                // Enumerating is the act under test; the failure arrives before any version is produced.
            }
        });

        Assert.Contains("oidc-sign/undated", exception.Message);
    }

    [Fact]
    public async Task UnwrapKeyAsync_RejectsUnsupportedAlgorithm_WithoutCallingTheVault()
    {
        // An algorithm this store cannot unwrap must be refused outright. Mapping it to something the vault does
        // accept would decrypt under an algorithm the caller never asked for.
        var handler = new StubHttpMessageHandler(_ =>
            throw new InvalidOperationException("the vault must not be called for an unsupported algorithm"));

        await Assert.ThrowsAsync<NotSupportedException>(() => ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc/v1",
            EncryptionAlgorithms.KeyManagement.EcdhEs,
            new JsonWebTokenHeader(new JsonObject()),
            [5, 5],
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SignAsync_Rs256_SignsThroughTheInjectedTransport()
    {
        var signature = new byte[] { 3, 1, 4, 1, 5, 9 };
        using var rsa = RSA.Create(2048);
        var handler = SignResponder("oidc-sign", signature, AzureResponses.KeyBundle(VaultUri, "oidc-sign", rsa.ExportParameters(false)));

        var result = await ClientOver(handler).SignAsync(
            "oidc-sign/v1", SigningAlgorithms.RS256, [9, 9], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_Es256_SignsThroughTheInjectedTransport()
    {
        var signature = new byte[] { 2, 7, 1, 8, 2, 8 };
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = SignResponder("oidc-sign", signature, AzureResponses.EcKeyBundle(VaultUri, "oidc-sign", ecdsa.ExportParameters(false)));

        var result = await ClientOver(handler).SignAsync(
            "oidc-sign/v1", SigningAlgorithms.ES256, [9, 9], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_RejectsUnsupportedAlgorithm()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));

        await Assert.ThrowsAsync<NotSupportedException>(() => ClientOver(handler)
            .SignAsync("oidc-sign/v1", "HS256", [1], TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task DecryptAsync_RsaOaep256_UnwrapsThroughTheInjectedTransport()
    {
        var plaintext = new byte[] { 2, 7, 1, 8 };
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, "oidc-enc", plaintext))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", rsa.ExportParameters(false))));

        var result = await ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc/v1", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [5, 5], TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnBadRequest()
    {
        // A rejected ciphertext is the ONE case that becomes null: the seam needs a wrong key to be
        // indistinguishable from bad padding, which is what closes the padding oracle.
        var result = await DecryptWithVaultAnswering(
            HttpStatusCode.BadRequest, """{"error":{"code":"BadParameter","message":"invalid ciphertext"}}""");

        Assert.Null(result);
    }

    [Fact]
    public async Task DecryptAsync_Throws_OnForbidden()
    {
        // The identity lost its Crypto User role. That is our fault, not the client's, and reporting it as a
        // failed decryption would tell every caller its JWE is bad while the vault is simply refusing us.
        await Assert.ThrowsAsync<RequestFailedException>(() => DecryptWithVaultAnswering(
            HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden","message":"denied"}}"""));
    }

    [Fact]
    public async Task DecryptAsync_Throws_OnThrottling()
    {
        // Key Vault throttles per vault, and this key sits on the token path, so 429 is routine rather than
        // exotic. Swallowing it as null would reject every encrypted token for as long as the throttle lasts,
        // silently, and blame the clients.
        await Assert.ThrowsAsync<RequestFailedException>(() => DecryptWithVaultAnswering(
            HttpStatusCode.TooManyRequests, """{"error":{"code":"Throttled","message":"slow down"}}"""));
    }

    private async Task<byte[]?> DecryptWithVaultAnswering(HttpStatusCode status, string body)
    {
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(status, body)
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", rsa.ExportParameters(false))));

        return await ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc/v1", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [5, 5], TestContext.Current.CancellationToken);
    }

    // The crypto client may fetch the key (a JIT GET) before the remote sign; return the key bundle for the GET and
    // the signature for the POST to /sign.
    private static StubHttpMessageHandler SignResponder(string keyName, byte[] signature, string keyBundle)
        => new(request => request.RequestUri!.AbsolutePath.EndsWith("/sign", StringComparison.Ordinal)
            ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, keyName, signature))
            : StubHttpMessageHandler.Json(HttpStatusCode.OK, keyBundle));

    /// <summary>
    /// Every JWS algorithm this store advertises is accepted and signed remotely, under a key of the type
    /// that algorithm needs.
    /// </summary>
    /// <remarks>
    /// The mapping to a Key Vault algorithm is a switch with nine reachable arms, of which two were walked.
    /// An unwalked arm is not merely unmeasured: a wrong one refuses an algorithm the store advertises, or
    /// names another, and both surface far from here.
    /// What this case does not assert, and the limit is worth stating rather than leaving to be discovered:
    /// the algorithm name on the wire. The SDK writes the request body through its own pipeline, so the
    /// message this transport seam receives carries no content to read. What it does assert is that the call
    /// reached the vault's sign endpoint - not a local signature, which a public-only key could not produce
    /// anyway - and came back with what the vault returned. Pinning the wire name needs the live backend,
    /// which is where the integration suite earns its place.
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.RS256)]
    [InlineData(SigningAlgorithms.RS384)]
    [InlineData(SigningAlgorithms.RS512)]
    [InlineData(SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.PS384)]
    [InlineData(SigningAlgorithms.PS512)]
    [InlineData(SigningAlgorithms.ES256)]
    [InlineData(SigningAlgorithms.ES384)]
    [InlineData(SigningAlgorithms.ES512)]
    public async Task SignAsync_AcceptsEveryAlgorithmItAdvertises(string jwsAlgorithm)
    {
        var signature = new byte[] { 1, 2, 3 };
        using var key = KeyFor(jwsAlgorithm);
        var handler = SignResponder("oidc-sign", signature, key.Bundle);

        var result = await ClientOver(handler).SignAsync(
            "oidc-sign/v1", jwsAlgorithm, [9, 9], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        Assert.Contains(
            handler.Requests,
            request => request.RequestUri!.AbsolutePath.EndsWith("/sign", StringComparison.Ordinal));
    }

    /// <summary>
    /// The same for key management: every algorithm this store advertises for unwrapping is accepted and
    /// unwrapped remotely.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep)]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5)]
    public async Task UnwrapKeyAsync_AcceptsEveryAlgorithmItAdvertises(string jweAlgorithm)
    {
        var unwrapped = new byte[] { 7, 7, 7 };
        using var rsa = RSA.Create(2048);
        var bundle = AzureResponses.KeyBundle(VaultUri, "oidc-enc", rsa.ExportParameters(false));

        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(
                    HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, "oidc-enc", unwrapped))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, bundle));

        var result = await ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc/v1", jweAlgorithm, new JsonWebTokenHeader(new JsonObject()), [5, 5],
            TestContext.Current.CancellationToken);

        Assert.Equal(unwrapped, result);
        Assert.Contains(
            handler.Requests,
            request => request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal));
    }

    /// <summary>
    /// A key id that does not name a version is refused before anything is sent.
    /// </summary>
    /// <remarks>
    /// The kid this client publishes is <c>name/version</c>, and the split is what turns it back into the two
    /// values the vault needs. A kid that cannot be split is not one this client minted - guessing a name from
    /// it would ask the vault to sign with whatever key happened to match.
    /// </remarks>
    [Theory]
    [InlineData("no-version-at-all")]
    [InlineData("/leading-slash")]
    [InlineData("trailing-slash/")]
    public async Task SignAsync_RefusesAKeyIdThatNamesNoVersion(string keyId)
    {
        var handler = new StubHttpMessageHandler(_ =>
            throw new InvalidOperationException("the vault must not be called for a malformed key id"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => ClientOver(handler).SignAsync(
            keyId, SigningAlgorithms.RS256, [9, 9], TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The credential is the configured service principal when all three of its parts are set, and the ambient
    /// Azure chain otherwise.
    /// </summary>
    /// <remarks>
    /// All three, not any: a half-configured principal is the case worth pinning. Falling back leaves a
    /// deployment authenticating as whatever ambient identity the host happens to carry - which may well
    /// succeed, and is then the wrong identity reaching a key store rather than a failure anyone notices.
    /// </remarks>
    /// <remarks>
    /// The unset cases are empty strings rather than nulls because that is the shape a deployment produces:
    /// the options carry <c>""</c> by default, and configuration binding leaves an absent key at that.
    /// </remarks>
    [Theory]
    [InlineData("tenant", "client", "secret", true)]
    [InlineData("", "client", "secret", false)]
    [InlineData("tenant", "", "secret", false)]
    [InlineData("tenant", "client", "", false)]
    [InlineData("   ", "client", "secret", false)]
    public void BuildCredential_UsesTheServicePrincipalOnlyWhenItIsComplete(
        string tenantId, string clientId, string clientSecret, bool expectServicePrincipal)
    {
        var credential = KeyVaultClient.BuildCredential(new AzureKeyVaultOptions
        {
            KeyVaultUri = VaultUri,
            TenantId = tenantId,
            ClientId = clientId,
            ClientSecret = clientSecret,
        });

        Assert.Equal(expectServicePrincipal, credential is ClientSecretCredential);
    }

    /// <summary>A key of the type the given JWS algorithm signs with, and the bundle the vault would return.</summary>
    private static SigningKey KeyFor(string algorithm) => algorithm switch
    {
        SigningAlgorithms.ES256 => SigningKey.Ec(ECCurve.NamedCurves.nistP256, "P-256"),
        SigningAlgorithms.ES384 => SigningKey.Ec(ECCurve.NamedCurves.nistP384, "P-384"),
        SigningAlgorithms.ES512 => SigningKey.Ec(ECCurve.NamedCurves.nistP521, "P-521"),
        _ => SigningKey.Rsa(),
    };

    /// <summary>A generated key together with the Key Vault bundle describing its public half.</summary>
    private sealed class SigningKey(IDisposable key, string bundle) : IDisposable
    {
        public string Bundle { get; } = bundle;

        public static SigningKey Rsa()
        {
            var rsa = RSA.Create(2048);
            return new SigningKey(rsa, AzureResponses.KeyBundle(VaultUri, "oidc-sign", rsa.ExportParameters(false)));
        }

        public static SigningKey Ec(ECCurve curve, string curveName)
        {
            var ecdsa = ECDsa.Create(curve);
            return new SigningKey(
                ecdsa, AzureResponses.EcKeyBundle(VaultUri, "oidc-sign", ecdsa.ExportParameters(false), curveName));
        }

        public void Dispose() => key.Dispose();
    }
}
