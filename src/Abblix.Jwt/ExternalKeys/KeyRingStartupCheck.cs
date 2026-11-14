// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Refuses, before anything is served, what would leave a partition opened later unable to serve or serving another's
/// keys: keys adopted into a partition the ring never keeps, or into the unnamed partition while the partitions come
/// and go, which no issuer is served from; one key adopted into two partitions; and a key-encryption key the
/// custodian cannot show, which a ring keeping no partition yet would otherwise first meet on its first tenant.
/// </summary>
/// <param name="setup">The policy and the partitions the ring is set up with.</param>
/// <param name="custodian">Holds the key-encryption key.</param>
internal sealed class KeyRingStartupCheck(KeyRingSetup setup, IKeyCustodian custodian)
{
    /// <summary>
    /// Throws when keys are adopted where no partition will take them, or one key into two partitions.
    /// </summary>
    /// <remarks>
    /// Judged before any partition opens: a partition takes adopted keys only until it holds a key it minted, so one
    /// opened before the refusal would mint, and the host correcting the adoption would never have its keys taken.
    /// </remarks>
    /// <exception cref="InvalidOperationException">One key is adopted into two partitions, keys are adopted into a
    /// partition the ring never keeps, or into the unnamed partition of a ring whose partitions come and go.
    /// </exception>
    public void CheckAdoption()
    {
        var policy = setup.Policy;

        // A fixed set names every partition the ring will meet; partitions added while it runs are not known yet
        if (setup.PartitionsKept.Fixed is { } fixedPartitions)
        {
            var unkept = policy.AdoptedKeys
                .Where(adopted => adopted.Value.Count > 0 && !fixedPartitions.Contains(adopted.Key, StringComparer.Ordinal))
                .Select(adopted => adopted.Key)
                .FirstOrDefault();

            if (unkept is not null)
            {
                throw new InvalidOperationException(
                    $"Existing keys are adopted into the partition '{unkept}', which the key ring never keeps, so no " +
                    "issuer is served them. Adopt them into the partition of the issuer that signs with them.");
            }
        }
        else if (policy.AdoptedKeys.GetValueOrDefault(KeyRingOptions.DefaultPartition) is { Count: > 0 })
        {
            throw new InvalidOperationException(
                "Existing keys are adopted into the unnamed partition of a key ring whose partitions come and go " +
                "while it runs, and no issuer is served from that partition. Adopt them into the partition of the " +
                "issuer that signs with them.");
        }

        // A key adopted into two partitions signs for both, so a party trusting one issuer's keys would verify the
        // other's tokens, which keys of their own exist to prevent. Judged after the partitions never kept, whose
        // refusal names the one edit that fixes it, while this one would leave the host to pick which partition keeps
        // the key. The key is compared by its thumbprint, so a copy under another key id is the same key, and a
        // repeat into one partition is no sharing
        var shared = (
            from adopted in policy.AdoptedKeys
            from key in adopted.Value
            group adopted.Key by key.ComputeJwkThumbprintBase64Url() into partitions
            let named = partitions.Distinct(StringComparer.Ordinal).ToArray()
            where named.Length > 1
            select (Thumbprint: partitions.Key, Partitions: named)).FirstOrDefault();

        if (shared.Partitions is not null)
        {
            throw new InvalidOperationException(
                $"The existing key with the thumbprint '{shared.Thumbprint}' is adopted into the partitions " +
                $"{string.Join(", ", shared.Partitions.Select(id => $"'{id}'"))}. Each partition signs with keys of its " +
                "own, so adopt a key into the partition of the one issuer that signs with it.");
        }
    }

    /// <summary>
    /// Throws when the custodian holds no version of the key-encryption key, which a ring keeping no partition yet
    /// would otherwise first meet on its first tenant.
    /// </summary>
    /// <exception cref="InvalidOperationException">The custodian holds no version of the key-encryption key.
    /// </exception>
    public async Task CheckKeyEncryptionKeyAsync(CancellationToken cancellationToken)
    {
        var policy = setup.Policy;
        if (await custodian.GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
                .AnyAsync(cancellationToken))
        {
            return;
        }

        throw new InvalidOperationException(
            $"The custodian holds no version of the key-encryption key '{policy.KeyEncryptionKeyName}', so the key " +
            "ring could open no key it mints.");
    }
}
