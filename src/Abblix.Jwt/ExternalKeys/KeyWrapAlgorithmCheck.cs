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
/// <param name="serviceProvider">The container the custodian is resolved from.</param>
/// <param name="builder">The builder holding the ring's policy as it stands after every registration call.</param>
internal sealed class KeyWrapAlgorithmCheck(IServiceProvider serviceProvider, MintedKeysBuilder builder)
    : IValidateOptions<KeyRingOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, KeyRingOptions options)
    {
        // A ring with no custodian is refused by the placement and seals nothing that could be checked here
        if (serviceProvider.GetService<IKeyCustodian>() is not { } custodian)
            return ValidateOptionsResult.Skip;

        var algorithm = builder.Policy.KeyWrapAlgorithm;
        return custodian.ServesKeyManagement(algorithm)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(CustodianEncryptionAlgorithmCheck.UnservedMessage(
                custodian, algorithm, $"{nameof(MintedKeys)}.{nameof(MintedKeys.KeyWrapAlgorithm)}"));
    }
}
