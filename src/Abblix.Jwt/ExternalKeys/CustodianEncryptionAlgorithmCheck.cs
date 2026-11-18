// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Stops the host when the encryption key held by the custodian is published with a key management algorithm the
/// custodian does not serve.
/// </summary>
/// <remarks>
/// A client encrypts exactly as the published key says, so every token it sends would fail to open, and nothing else
/// would say why until the first one does. The keys are read from the container rather than taken as they were
/// passed, because a host may supply them from a factory that reads its configuration.
/// </remarks>
/// <param name="serviceProvider">The container the custodian and its keys are resolved from.</param>
internal sealed class CustodianEncryptionAlgorithmCheck(IServiceProvider serviceProvider)
    : IValidateOptions<KeyPlacementChoice>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, KeyPlacementChoice options)
    {
        if (options.ChosenPlacement != KeyPlacement.Custodian ||
            serviceProvider.GetService<CustodianHeldKeys>() is not { EncryptionKeyName: not null } keys)
        {
            return ValidateOptionsResult.Skip;
        }

        var custodian = serviceProvider.GetRequiredService<IKeyCustodian>();
        return custodian.ServesKeyManagement(keys.EncryptionAlgorithm)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(UnservedMessage(
                custodian, keys.EncryptionAlgorithm, $"{nameof(CustodianHeldKeys)}.{nameof(CustodianHeldKeys.EncryptionAlgorithm)}"));
    }

    /// <summary>
    /// What a host is told when a key management algorithm it chose is one its custodian does not serve.
    /// </summary>
    /// <param name="custodian">The custodian that does not serve the algorithm.</param>
    /// <param name="algorithm">The algorithm the host chose.</param>
    /// <param name="setting">The setting that chose it.</param>
    internal static string UnservedMessage(IKeyCustodian custodian, string algorithm, string setting)
        => $"The key custodian {custodian.GetType().Name} does not serve the key management algorithm " +
           $"'{algorithm}' that {setting} names, so nothing encrypted under it could be opened. Choose an " +
           "algorithm the custodian serves.";
}
