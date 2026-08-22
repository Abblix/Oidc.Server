// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.Azure.UnitTests;

/// <summary>
/// Drives <see cref="KeyVaultClient"/> against a REAL Key Vault, which the stub suite cannot do: a stub answers
/// whatever the test wrote into it, so it proves the branch is wired and nothing about what Key Vault actually
/// reports. Disabling a version is how an operator revokes a compromised key, and the whole value of the guard is
/// that the vault's own answer reaches it.
///
/// Skipped unless <c>ABBLIX_LIVE_KEY_VAULT_URI</c> names a vault, so CI, which has no vault and no sign-in, runs
/// the suite unchanged.
/// </summary>
public sealed class LiveKeyVaultTests : IDisposable
{
    private const string VaultUriVariable = "ABBLIX_LIVE_KEY_VAULT_URI";

    private readonly HttpClient _httpClient = new();

    public void Dispose() => _httpClient.Dispose();

    /// <summary>
    /// The product's chain with an interactive tail: a machine carrying a managed identity or an Azure CLI sign-in
    /// authenticates silently, and one with neither gets a browser prompt rather than an authentication failure
    /// nobody can act on. The prompt caches its token on disk, so signing in once covers the re-runs this check
    /// needs - without that, every run of a test whose whole point is to be run twice opens a browser again.
    /// </summary>
    private static TokenCredential Credential()
        => new ChainedTokenCredential(
            new AzureCliCredential(),
            new AzurePowerShellCredential(),
            new InteractiveBrowserCredential(new InteractiveBrowserCredentialOptions
            {
                TokenCachePersistenceOptions = new TokenCachePersistenceOptions { Name = "abblix-live-key-vault" },
            }));

    [Fact]
    public async Task GetKeyVersionsAsync_DoesNotPublishAVersionTheVaultReportsAsDisabled()
    {
        var vaultUri = Environment.GetEnvironmentVariable(VaultUriVariable);
        if (string.IsNullOrWhiteSpace(vaultUri))
        {
            Assert.Skip($"Set {VaultUriVariable} to a vault endpoint to run this against a live vault.");
            return;
        }

        var cancellationToken = TestContext.Current.CancellationToken;
        var uri = new Uri(vaultUri);
        var credential = Credential();

        // Two readers of one vault: the SDK client supplies the expectation and the custodian is what the
        // expectation judges. Deriving both from the custodian would let one defect satisfy itself.
        var keyClient = new KeyClient(uri, credential);
        var custodian = new KeyVaultClient(
            NullLogger<KeyVaultClient>.Instance,
            new AzureKeyVaultOptions { KeyVaultUri = uri },
            credential,
            _httpClient);

        var keyNames = await keyClient.GetPropertiesOfKeysAsync(cancellationToken)
            .Select(key => key.Name)
            .ToListAsync(cancellationToken);

        var disabledSeen = 0;
        var publishedAnything = 0;
        foreach (var keyName in keyNames)
        {
            var reported = new List<(string Version, bool Enabled)>();
            await foreach (var version in keyClient.GetPropertiesOfKeyVersionsAsync(keyName, cancellationToken))
                reported.Add((version.Version, version.Enabled == true));

            var published = new List<string>();
            await foreach (var version in custodian.GetKeyVersionsAsync(keyName, cancellationToken))
            {
                // A published version without a kid is itself a defect: the kid is how a verifier addresses the
                // version. Assert rather than suppress, so the run says which key produced one.
                var keyId = version.PublicKey.KeyId;
                Assert.NotNull(keyId);
                published.Add(keyId);
            }

            var expected = reported
                .Where(version => version.Enabled)
                .Select(version => $"{keyName}/{version.Version}")
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();

            Assert.Equal(expected, published.OrderBy(id => id, StringComparer.Ordinal).ToList());

            disabledSeen += reported.Count(version => !version.Enabled);
            publishedAnything += published.Count;
        }

        // Two ways this run could report a pass it has not earned, both refused here rather than above, so the
        // comparisons still run and a real mismatch is still reported first.
        //
        // With every version in the vault enabled, "published exactly the enabled ones" is trivially true and no
        // defect in the custodian could have made it false.
        Assert.SkipWhen(
            disabledSeen == 0,
            $"No disabled key version in {uri}. Disable one version of any key there and re-run - with every " +
            "version enabled this test cannot fail.");

        // And a custodian that published nothing at all satisfies the comparison for every key, so passing must
        // mean "skips the disabled ones" rather than "returns nothing".
        Assert.True(
            publishedAnything > 0,
            $"The custodian published no key version at all from {uri}, so this run cannot tell a working " +
            "skip from a broken listing.");
    }
}
