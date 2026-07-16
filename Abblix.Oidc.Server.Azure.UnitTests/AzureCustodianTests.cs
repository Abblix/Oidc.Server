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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Verifies the algorithm gate of <see cref="AzureCustodian"/>. The vault client is constructed offline (the
/// Azure SDK clients connect lazily), so each guard is exercised without a live vault: it rejects the unsupported
/// algorithm before the client would be called. The happy-path sign / unwrap round-trip needs a live Key Vault
/// and is covered by end-to-end verification, not a unit test.
/// </summary>
public class AzureCustodianTests
{
    private static AzureCustodian Custodian()
        => new(new AzureKeyVaultClient(Options.Create(
            new AzureKeyVaultOptions { KeyVaultUri = "https://contoso.vault.azure.net/" })));

    [Fact]
    public async Task SignAsync_RejectsNonRs256()
    {
        await Assert.ThrowsAsync<NotSupportedException>(() => Custodian()
            .SignAsync("oidc-sign", "ES256", new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task UnwrapKeyAsync_RejectsNonRsaOaep256()
    {
        await Assert.ThrowsAsync<NotSupportedException>(() => Custodian().UnwrapKeyAsync(
            "oidc-enc", "RSA1_5", new JsonWebTokenHeader(new JsonObject()),
            new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public void AgreeKeyAsync_IsNotSupported()
    {
        Assert.Throws<NotSupportedException>(() => _ = Custodian().AgreeKeyAsync(
            "oidc-enc", "ECDH-ES", new RsaJsonWebKey(), TestContext.Current.CancellationToken));
    }
}
