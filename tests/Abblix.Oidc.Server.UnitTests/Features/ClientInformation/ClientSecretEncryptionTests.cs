// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// RFC 7592 section 3 has a read "return all registered metadata about this client", and Appendix A.1 has "The
/// client's current registration access token and client credentials (if applicable) MUST be included in the client
/// information response". A tenant with a client secret encryption key keeps each secret it issues encrypted for its
/// client, so a read returns it; a value moved to another client or tenant, read under a replaced key, or kept by a
/// tenant without a key returns no secret, and a stored client written before the member existed reads unchanged.
/// </summary>
public class ClientSecretEncryptionTests
{
    private const string ClientId = "client-1";
    private const string Secret = "the-secret-issued";
    private const string TokenId = "jti";

    private static string NewKey() => Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    private static TenantDefinition TenantWith(string? key, string id = "acme") => new()
    {
        Id = id,
        Issuer = new Uri($"https://{id}.example.com"),
        ClientSecretEncryption = key is null ? null : new ClientSecretEncryptionSettings { Key = key },
    };

    private static IClientSecretEncryptor Encryptor(RecordingLoggerFactory? log = null) => new IssuerClientSecretEncryptor(
        (log ?? new RecordingLoggerFactory()).CreateLogger<IssuerClientSecretEncryptor>(),
        SingleIssuer.LocalOf<ClientSecretEncryptor>());

    private static async Task<string?> ReadSecretAsync(
        TenantDefinition tenant,
        ClientInfo client,
        RecordingLoggerFactory? log = null)
    {
        var tokens = new Mock<IRegistrationAccessTokenService>(MockBehavior.Loose);
        tokens.Setup(s => s.IssueTokenAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(),
                It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        var processor = new ReadClientRequestProcessor(tokens.Object, TimeProvider.System, Encryptor(log));
        var result = await processor.ProcessAsync(
            tenant, new ValidClientRequest(new ClientRequest(), new RegisteredClient(client, TokenId)));

        Assert.True(result.TryGetSuccess(out var response));
        return response.ClientSecret;
    }

    private static ClientInfo ClientHolding(byte[]? encrypted, string clientId = ClientId) => new(clientId)
    {
        ClientSecrets = [new ClientSecret { Sha512Hash = new byte[64], EncryptedValue = encrypted }],
    };

    [Fact]
    public async Task AReadReturnsTheSecretTheTenantKeptEncrypted()
    {
        var tenant = TenantWith(NewKey());
        var encrypted = Encryptor().Encrypt(tenant, ClientId, Secret);

        Assert.NotNull(encrypted);
        Assert.Equal(Secret, await ReadSecretAsync(tenant, ClientHolding(encrypted)));
    }

    [Fact]
    public async Task ASecretMovedToAnotherClient_IsNotReturned()
    {
        var tenant = TenantWith(NewKey());
        var encrypted = Encryptor().Encrypt(tenant, ClientId, Secret);

        Assert.Null(await ReadSecretAsync(tenant, ClientHolding(encrypted, clientId: "client-2")));
    }

    [Fact]
    public async Task ASecretMovedToAnotherTenantUnderTheSameKey_IsNotReturned()
    {
        var key = NewKey();
        var encrypted = Encryptor().Encrypt(TenantWith(key), ClientId, Secret);

        Assert.Null(await ReadSecretAsync(TenantWith(key, id: "other"), ClientHolding(encrypted)));
    }

    [Fact]
    public async Task ASecretEncryptedUnderAReplacedKey_IsNotReturnedAndIsLogged()
    {
        var encrypted = Encryptor().Encrypt(TenantWith(NewKey()), ClientId, Secret);
        var log = new RecordingLoggerFactory();

        Assert.Null(await ReadSecretAsync(TenantWith(NewKey()), ClientHolding(encrypted), log));

        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogEvents.ClientInformation.ClientSecretEncryption.SecretNotDecrypted, entry.EventId.Id);
        Assert.Equal(LogLevel.Warning, entry.Level);
    }

    [Fact]
    public async Task ATenantWithoutAKey_RefusesToEncryptAndReturnsNoSecret()
    {
        var tenant = TenantWith(null);

        Assert.Throws<InvalidOperationException>(() => Encryptor().Encrypt(tenant, ClientId, Secret));
        Assert.Null(await ReadSecretAsync(tenant, ClientHolding(new byte[40])));
    }

    /// <summary>
    /// A server serving dynamic client registration refuses a tenant without the key, naming the setting, since a
    /// client reading its registration is given its secret back; a server not serving it lets the tenant through.
    /// </summary>
    [Theory]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    public void ATenantWithoutAKey_IsRefusedWhileRegistrationIsServed(bool registrationServed, bool keyed, bool refused)
    {
        var options = new OidcOptions();
        if (registrationServed)
            options.EnabledEndpoints |= OidcEndpoints.RegisterClient;
        else
            options.EnabledEndpoints &= ~OidcEndpoints.RegisterClient;

        var refusals = new TenantDefinitionsCheck()
            .Check([TenantWith(keyed ? NewKey() : null)], options)
            .Select(refusal => refusal.Message)
            .ToArray();

        Assert.Equal(refused, refusals.Any(
            failure => failure.Contains(nameof(TenantDefinition.ClientSecretEncryption), StringComparison.Ordinal)));
    }

    /// <summary>
    /// A secret stored by 3.0 carries no encrypted value: its JSON reads unchanged, and a read answers without it.
    /// </summary>
    [Fact]
    public async Task ASecretStoredBeforeTheMemberExisted_ReadsUnchangedAndIsNotReturned()
    {
        var hash = new byte[64];
        var stored = $$"""{"Sha512Hash":"{{Convert.ToBase64String(hash)}}","ExpiresAt":null}""";

        var secret = JsonSerializer.Deserialize<ClientSecret>(stored)!;

        Assert.Equal(hash, secret.Sha512Hash);
        Assert.Null(secret.EncryptedValue);
        Assert.Null(await ReadSecretAsync(
            TenantWith(NewKey()), new ClientInfo(ClientId) { ClientSecrets = [secret] }));
    }

    [Fact]
    public void TheEncryptedValue_SurvivesTheStoreAndStaysOutOfTheLog()
    {
        var secret = new ClientSecret { EncryptedValue = [1, 2, 3] };

        var read = JsonSerializer.Deserialize<ClientSecret>(JsonSerializer.Serialize(secret))!;

        Assert.Equal(secret.EncryptedValue, read.EncryptedValue);
        Assert.DoesNotContain("AQID", secret.ToString());
        Assert.Contains("EncryptedValue = set", secret.ToString());
    }

    [Theory]
    [InlineData(null, "SHA256", true)]
    [InlineData("c2hvcnQ=", "SHA256", true)]
    [InlineData("valid", "MD5", true)]
    [InlineData("valid", "SHA512", false)]
    public void ATenantsKey_IsJudgedWhenTheTenantEntersTheServer(string? key, string hashAlgorithm, bool refused)
    {
        var tenant = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri("https://auth.example.com"),
            ClientSecretEncryption = new ClientSecretEncryptionSettings
            {
                Key = key == "valid" ? NewKey() : key!,
                HashAlgorithm = hashAlgorithm,
            },
        };

        var refusals = new TenantDefinitionsCheck().Check([tenant], new OidcOptions());

        Assert.Equal(refused, refusals.Any());
    }
}
