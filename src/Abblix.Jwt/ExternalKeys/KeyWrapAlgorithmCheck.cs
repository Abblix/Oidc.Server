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
/// Stops the host when its key ring seals keys under a key wrap algorithm the custodian does not serve.
/// </summary>
/// <remarks>
/// The ring seals in process, with the public half of the custodian's key, so sealing succeeds and only opening a
/// key fails: without this check the ring would mint and share keys no instance can open.
/// </remarks>
/// <param name="serviceProvider">The container the custodian and the ring's policy are resolved from.</param>
internal sealed class KeyWrapAlgorithmCheck(IServiceProvider serviceProvider) : IValidateOptions<KeyRingOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, KeyRingOptions options)
    {
        // With no custodian, or no ring minting keys, there is nothing to compare the algorithm with
        if (serviceProvider.GetService<IKeyCustodian>() is not { } custodian ||
            serviceProvider.GetService<MintedKeysBuilder>() is not { } builder)
        {
            return ValidateOptionsResult.Skip;
        }

        var algorithm = builder.Policy.KeyWrapAlgorithm;
        return custodian.ServesKeyManagement(algorithm)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(CustodianEncryptionAlgorithmCheck.UnservedMessage(
                custodian, algorithm, $"{nameof(MintedKeys)}.{nameof(MintedKeys.KeyWrapAlgorithm)}"));
    }
}
