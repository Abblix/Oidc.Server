// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses a tenant declaring keys the library's key provider never reads; with the keys coming from each tenant's
/// settings, a tenant declaring no signing key, a key lacking a member its type requires, or a key another tenant
/// declares; and, with the keys held by a custodian, whether or not a key provider of the host's own stands in front
/// of the library's, a tenant naming no key there or one another tenant names.
/// </summary>
/// <param name="serviceProvider">Tells which key provider serves the keys, and resolves the custodian.</param>
public sealed class TenantKeysCheck(IServiceProvider serviceProvider) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
    {
        var registration = serviceProvider.GetService<KeyProviderRegistration>();
        return registration?.Kind switch
        {
            KeyProviderKind.Settings => Unread(tenants, "the keys come from each tenant's settings",
                    nameof(TenantDefinition.SigningKeys), nameof(TenantDefinition.EncryptionKeys))
                .Concat(UnsignedOf(tenants))
                .Concat(UndersizedSettingsKeysOf(tenants))
                .Concat(IncompleteSettingsKeysOf(tenants))
                .Concat(SharedSettingsKeysOf(tenants)),

            KeyProviderKind.Custodian => Unread(tenants, "the keys are held by a custodian",
                    nameof(TenantDefinition.CustodianKeys))
                .Concat(NamedInTheCustodianOf(tenants)),

            KeyProviderKind.Minted => Unread(tenants, "the server mints the keys"),

            // A provider of the host's own in front of the custodian, as the cache a host keeps there, still serves
            // the keys each tenant names in it; what the provider reads of the settings is its own
            KeyProviderKind.Host when registration is { Placed: KeyProviderKind.Custodian }
                => NamedInTheCustodianOf(tenants),

            // Over any other placement a key provider of the host's own answers for each tenant's keys itself
            KeyProviderKind.Host => [],

            // No key provider is registered, so no tenant's keys are read
            null => [],

            var unknown => throw new InvalidOperationException($"Unexpected {nameof(KeyProviderKind)} '{unknown}'."),
        };
    }

    /// <summary>
    /// The keys each tenant names in the custodian: named at all, by no other tenant, and for encryption under an
    /// algorithm the custodian serves.
    /// </summary>
    private IEnumerable<TenantRefusal> NamedInTheCustodianOf(IReadOnlyCollection<TenantDefinition> tenants)
        => CustodianKeysOf(tenants)
            .Concat(UnservedEncryptionOf(
                tenants,
                serviceProvider.GetRequiredService<IKeyCustodian>(),
                serviceProvider.GetRequiredService<EncryptionAlgorithmsProvider>()));

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
    /// No signing key a tenant declares is smaller than RFC 7518 lets it sign with: an RSA key below 2048 bits
    /// (sections 3.3 and 3.5), a symmetric key shorter than the hash output of its algorithm (section 3.2). Such a key
    /// signs nothing, and found missing at the first token it would read as a key that is not there. A key without the
    /// material to measure is refused as incomplete instead.
    /// </summary>
    private static IEnumerable<TenantRefusal> UndersizedSettingsKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
        => (from tenant in tenants
            from key in tenant.SigningKeys
            where key.HasPublicKey
            select UndersizedRefusal(tenant, key))
           .OfType<TenantRefusal>();

    private static TenantRefusal? UndersizedRefusal(TenantDefinition tenant, JsonWebKey key)
        => SigningKeyFloor.Undersized(key) is { } size
            ? TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': The signing key '{key.KeyId}' has {size.Bits} bits, below the {size.Floor} " +
                $"RFC 7518 requires of it, so nothing is signed with it. Replace it with a key of at least " +
                $"{size.Floor} bits.")
            : null;

    /// <summary>
    /// No key, compared by its thumbprint, is declared by two tenants: sharing one would let a party trusting one
    /// tenant's keys verify the other's tokens, or open what was encrypted to it, which keys of their own exist to
    /// prevent.
    /// </summary>
    /// <remarks>
    /// A tenant may declare one key in both roles or twice, so each tenant counts once per key. A key lacking a member
    /// its type requires has no thumbprint and is refused on its own (<see cref="IncompleteSettingsKeysOf"/>).
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
                "its own.")
            {
                PartyMessage = $"the key with the thumbprint '{declarers.Key}' it declares is declared by another " +
                               "tenant; each tenant signs and decrypts with keys of its own.",
            };

    /// <summary>
    /// A key a tenant declares without every member its key type requires can neither be published nor told apart
    /// from another tenant's, so the tenant is refused once, naming each such key, and the tenants beside it are served.
    /// </summary>
    private static IEnumerable<TenantRefusal> IncompleteSettingsKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
        => TenantRefusal.EachOf(tenants, IncompleteKeysOf);

    private static IEnumerable<string> IncompleteKeysOf(TenantDefinition tenant)
    {
        var incomplete = tenant.SigningKeys.Concat(tenant.EncryptionKeys)
            .Where(key => !key.HasPublicKey)
            .Select(key => key.KeyId is { } keyId ? $"'{keyId}' ({key.KeyType})" : $"one with no key id ({key.KeyType})")
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (incomplete.Length == 1)
        {
            yield return $"the key {incomplete[0]} it declares lacks a member its key type requires, so it can be " +
                         "neither published nor compared with another tenant's keys.";
        }
        else if (incomplete.Length > 1)
        {
            yield return $"the keys {string.Join(", ", incomplete)} it declares lack a member their key type " +
                         "requires, so they can be neither published nor compared with another tenant's keys.";
        }
    }

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
                "each tenant produces with keys of its own.")
            {
                PartyMessage = $"the custodian key '{namers.Key}' it names is named by another tenant; each tenant " +
                               "produces with keys of its own.",
            };

        return unnamed.Concat(shared);
    }

    /// <summary>
    /// A tenant whose encryption key the custodian holds publishes it with a key management algorithm the custodian
    /// serves and the host registers: a client encrypts exactly as the published key says, and an inbound JWE is
    /// tried with a key only under an algorithm registered for it, so under any other every token sent to the
    /// tenant would fail to open.
    /// </summary>
    private static IEnumerable<TenantRefusal> UnservedEncryptionOf(
        IReadOnlyCollection<TenantDefinition> tenants,
        IKeyCustodian custodian,
        EncryptionAlgorithmsProvider encryptionAlgorithms)
        =>
            from tenant in tenants
            where tenant.CustodianKeys is { EncryptionKeyName: not null }
            let algorithm = tenant.CustodianKeys!.EncryptionAlgorithm
            let unserved = WhoDoesNotServe(algorithm, custodian, encryptionAlgorithms)
            where unserved is not null
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': {unserved} the key management algorithm '{algorithm}' that " +
                $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.CustodianKeys)}." +
                $"{nameof(CustodianHeldKeys.EncryptionAlgorithm)} names, so no token encrypted to the tenant could be " +
                "opened.");

    /// <summary>
    /// Which of the two parties an inbound JWE under <paramref name="algorithm"/> needs fails it, said as the start of
    /// the refusal, or null where both serve it.
    /// </summary>
    private static string? WhoDoesNotServe(
        string algorithm,
        IKeyCustodian custodian,
        EncryptionAlgorithmsProvider encryptionAlgorithms)
    {
        if (!custodian.ServesKeyManagement(algorithm))
            return $"the key custodian {custodian.GetType().Name} does not serve";

        if (!encryptionAlgorithms.KeyManagementAlgorithms.Contains(algorithm, StringComparer.Ordinal))
            return "the host registers no implementation of";

        return null;
    }
}
