// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Refuses, before anything is served, what would leave a partition opened later unable to serve: keys adopted into
/// the unnamed partition while the partitions come and go, which no issuer is served from, and a key-encryption key
/// the custodian cannot show, which a ring keeping no partition yet would otherwise first meet on its first tenant.
/// </summary>
/// <param name="setup">The policy and the partitions the ring is set up with.</param>
/// <param name="custodian">Holds the key-encryption key.</param>
internal sealed class KeyRingStartupCheck(KeyRingSetup setup, IKeyCustodian custodian)
{
    /// <summary>
    /// Throws when the ring could not serve a partition opened later.
    /// </summary>
    /// <exception cref="InvalidOperationException">Keys are adopted into the unnamed partition of a ring whose
    /// partitions come and go, or the custodian holds no version of the key-encryption key.</exception>
    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        var policy = setup.Policy;

        // The settings' partitions are fixed at startup, so the ring meets each of them now; a host's own come later
        if (policy.AdoptedKeys.GetValueOrDefault(KeyRingOptions.DefaultPartition) is { Count: > 0 } &&
            setup.PartitionsKept is not OptionsKeyRingPartitions)
        {
            throw new InvalidOperationException(
                "Existing keys are adopted into the unnamed partition of a key ring whose partitions come and go " +
                "while it runs, and no issuer is served from that partition. Adopt them into the partition of the " +
                "issuer that signs with them.");
        }

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
