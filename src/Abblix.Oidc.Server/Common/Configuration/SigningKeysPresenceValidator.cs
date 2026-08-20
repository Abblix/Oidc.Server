// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses to start a host that can never sign a token, instead of letting it come up healthy and
/// fail at the first issuance - or, worse, serve an empty JWKS that every relying party caches.
/// </summary>
/// <remarks>
/// The library deliberately never generates a signing key, so a host that supplies none has no
/// fallback to land on. The refusal is confined to the one state that is provably hopeless without
/// touching any backend: the resolved provider is the library's own static one, no custodian is
/// wired, and <see cref="OidcOptions.SigningKeys"/> is empty - a condition fully known at startup.
/// A host-supplied provider is trusted and never probed here, because its store may legitimately be
/// unreachable while the host boots (pending migrations, a sealed vault), and a startup probe would
/// turn that into a refusal to start. A custodian half-wired without its placement call is also left
/// alone: the provider itself refuses that state with a message naming the missing call.
/// </remarks>
internal sealed class SigningKeysPresenceValidator(IServiceProvider serviceProvider)
    : IValidateOptions<OidcOptions>
{
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        // Resolved here rather than through the constructor: the options factory constructs every
        // registered validator inside its own constructor, and the default keys provider takes
        // IOptions<OidcOptions>, so a constructor dependency on the provider closes a cycle the
        // container cannot see through the provider's factory lambda - it overflows the stack
        // instead of reporting a circular dependency. By the time Validate runs the factory is
        // fully built, and the same resolution completes without re-entering it.
        var keysProvider = serviceProvider.GetRequiredService<IAuthServiceKeysProvider>();
        var custodian = serviceProvider.GetService<IKeyCustodian>();

        if (keysProvider is not OidcOptionsKeysProvider || custodian is not null)
            return ValidateOptionsResult.Success;

        if (options.SigningKeys.Count > 0)
            return ValidateOptionsResult.Success;

        return ValidateOptionsResult.Fail(
            $"No signing key is configured, so the server cannot issue a single token and publishes an empty JWKS. " +
            $"The library does not generate keys: supply at least one JWK with a private part in " +
            $"{nameof(OidcOptions)}.{nameof(OidcOptions.SigningKeys)}, or register your own " +
            $"{nameof(IAuthServiceKeysProvider)} that reads keys from where your deployment keeps them " +
            "(the Vault and Azure key packages ship such providers).");
    }
}
