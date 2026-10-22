// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses a tenant declaring keys its server's placement never reads; with the keys coming from each tenant's
/// settings, a tenant declaring no signing key, a key lacking a member its type requires, or a key another tenant
/// declares; and,
/// with the keys held by a custodian, a tenant naming no key there or one another tenant names.
/// </summary>
/// <param name="serviceProvider">Tells which key provider serves the keys, and resolves the custodian.</param>
public sealed class TenantKeysCheck(IServiceProvider serviceProvider) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => serviceProvider.GetService<KeyProviderRegistration>()?.Kind switch
        {
            KeyProviderKind.Settings => Unread(tenants, "the keys come from each tenant's settings",
                    nameof(TenantDefinition.SigningKeys), nameof(TenantDefinition.EncryptionKeys))
                .Concat(UnsignedOf(tenants))
                .Concat(IncompleteSettingsKeysOf(tenants))
                .Concat(SharedSettingsKeysOf(tenants)),

            KeyProviderKind.Custodian => Unread(tenants, "the keys are held by a custodian",
                    nameof(TenantDefinition.CustodianKeys))
                .Concat(CustodianKeysOf(tenants))
                .Concat(UnservedEncryptionOf(tenants, serviceProvider.GetRequiredService<IKeyCustodian>())),

            KeyProviderKind.Minted => Unread(tenants, "the server mints the keys"),

            // A key provider of the host's own answers for each tenant's keys itself, so nothing here judges them
            KeyProviderKind.Host => [],

            // No key provider is registered, so no tenant's keys are read
            null => [],

            var unknown => throw new InvalidOperationException($"Unexpected {nameof(KeyProviderKind)} '{unknown}'."),
        };

    /// <summary>
    /// A tenant whose keys come from its settings and that declares no signing key cannot issue a single token and
    /// publishes an empty key set, which every relying party caches.
    /// </summary>
    /// <remarks>
    /// The library never generates a signing key, so the tenant has nothing to fall back on. A custodian half-wired
    /// without its placement call leaves the settings' provider registered beside it, and that provider refuses
    /// the state itself, naming the missing call, so it is not judged here.
    /// </remarks>
    private IEnumerable<TenantRefusal> UnsignedOf(IReadOnlyCollection<TenantDefinition> tenants)
        => serviceProvider.GetService<IKeyCustodian>() is not null
            ? []
            :
            from tenant in tenants
            where tenant.SigningKeys.Count == 0
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': No signing key is declared, so the tenant cannot issue a single token and " +
                $"publishes an empty JWKS. Supply at least one JWK with a private part in " +
                $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.SigningKeys)}, or have the keys held by a " +
                "custodian or minted by the server.");

    /// <summary>
    /// No key, compared by its thumbprint, is declared by two tenants: sharing one would let a party trusting one
    /// tenant's keys verify the other's tokens, or open what was encrypted to it, which keys of their own exist to
    /// prevent.
    /// </summary>
    /// <remarks>
    /// A tenant may declare one key in both roles or twice, so each tenant counts once per key. A key with no public
    /// type requires has no thumbprint and is refused on its own (<see cref="IncompleteSettingsKeysOf"/>).
    /// </remarks>
    private static IEnumerable<TenantRefusal> SharedSettingsKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
        =>
            from tenant in tenants
            from thumbprint in tenant.SigningKeys.Concat(tenant.EncryptionKeys)
                .Where(key => key.HasPublicKey)
                .Select(key => key.ComputeJwkThumbprintBase64Url())
                .Distinct(StringComparer.Ordinal)
            group tenant.Id by thumbprint into declarers
            where declarers.Count() > 1
            select new TenantRefusal(
                [..declarers],
                $"The key with the thumbprint '{declarers.Key}' is declared by the tenants " +
                $"{string.Join(", ", declarers.Select(id => $"'{id}'"))}; each tenant signs and decrypts with keys of " +
                "its own.");

    /// <summary>
    /// A key a tenant declares without every member its key type requires can neither be published nor told apart
    /// from another tenant's, so the tenant is refused once, naming each such key, and the tenants beside it are served.
    /// </summary>
    private static IEnumerable<TenantRefusal> IncompleteSettingsKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
        =>
            from tenant in tenants
            let incomplete = tenant.SigningKeys.Concat(tenant.EncryptionKeys)
                .Where(key => !key.HasPublicKey)
                .Select(key => key.KeyId is { } keyId
                    ? $"'{keyId}' ({key.KeyType})"
                    : $"one with no key id ({key.KeyType})")
                .Distinct(StringComparer.Ordinal)
                .ToArray()
            where incomplete.Length > 0
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': the keys {string.Join(", ", incomplete)} it declares lack a member their key " +
                "type requires, so they can be neither published nor compared with another tenant's keys.");

    /// <summary>
    /// The key settings a tenant declares that the placement never reads: declared, they read as the keys the
    /// tenant produces with while it produces with others.
    /// </summary>
    private static IEnumerable<TenantRefusal> Unread(IReadOnlyCollection<TenantDefinition> tenants, string placement, params string[] read)
        =>
            from tenant in tenants
            from setting in Declared(tenant)
            where !read.Contains(setting, StringComparer.Ordinal)
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': {nameof(TenantDefinition)}.{setting} is declared, but {placement}, " +
                "so it is never read.");

    private static IEnumerable<string> Declared(TenantDefinition tenant)
    {
        if (tenant.SigningKeys.Count > 0)
            yield return nameof(TenantDefinition.SigningKeys);
        if (tenant.EncryptionKeys.Count > 0)
            yield return nameof(TenantDefinition.EncryptionKeys);
        if (tenant.CustodianKeys is not null)
            yield return nameof(TenantDefinition.CustodianKeys);
    }

    /// <summary>
    /// Each tenant names keys in the custodian, and no key is named by two tenants: sharing one would let a party
    /// trusting one tenant's keys verify the other's tokens, which keys of their own exist to prevent.
    /// </summary>
    private static IEnumerable<TenantRefusal> CustodianKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
    {
        var unnamed =
            from tenant in tenants
            where tenant.CustodianKeys is null
            select TenantRefusal.Of(tenant, $"Tenant '{tenant.Id}': {ExternalKeysProvider.NoKeyNamed}");

        // A tenant may name one key for both roles, so each tenant counts once per key
        var shared =
            from tenant in tenants
            where tenant.CustodianKeys is not null
            from keyName in new[] { tenant.CustodianKeys!.SigningKeyName, tenant.CustodianKeys.EncryptionKeyName }
                .Distinct(StringComparer.Ordinal)
            where keyName is not null
            group tenant.Id by keyName into namers
            where namers.Count() > 1
            select new TenantRefusal(
                [..namers],
                $"The custodian key '{namers.Key}' is named by the tenants " +
                $"{string.Join(", ", namers.Select(id => $"'{id}'"))}; " +
                "each tenant produces with keys of its own.");

        return unnamed.Concat(shared);
    }

    /// <summary>
    /// A tenant whose encryption key the custodian holds publishes it with a key management algorithm the custodian
    /// serves: a client encrypts exactly as the published key says, so under any other every token sent to the
    /// tenant would fail to open.
    /// </summary>
    private static IEnumerable<TenantRefusal> UnservedEncryptionOf(
        IReadOnlyCollection<TenantDefinition> tenants,
        IKeyCustodian custodian)
        =>
            from tenant in tenants
            where tenant.CustodianKeys is { EncryptionKeyName: not null } keys &&
                  !custodian.ServesKeyManagement(keys.EncryptionAlgorithm)
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': the key custodian {custodian.GetType().Name} does not serve the key " +
                $"management algorithm '{tenant.CustodianKeys!.EncryptionAlgorithm}' that " +
                $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.CustodianKeys)}." +
                $"{nameof(CustodianHeldKeys.EncryptionAlgorithm)} names, so no token encrypted to the tenant could be " +
                "opened.");
}
