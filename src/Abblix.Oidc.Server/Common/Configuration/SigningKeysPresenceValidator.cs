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
using Abblix.Oidc.Server.Features.ExternalKeys;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
        // Under multi-tenancy the server's own settings carry no keys and each tenant's carry its own; the
        // custodian's key names are a tenant's own and judged with the tenant list
        if (MultiTenancyDetection.IsActive(serviceProvider))
        {
            return MultiTenancyDetection.IsTenantsOwn(options) &&
                   KeysComeFromSettings(serviceProvider) &&
                   options.SigningKeys.Count == 0
                ? ValidateOptionsResult.Fail(NoTenantSigningKey)
                : ValidateOptionsResult.Success;
        }

        if (KeysComeFromSettings(serviceProvider))
        {
            return options.SigningKeys.Count > 0
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(NoSigningKey);
        }

        return serviceProvider.GetService<IAuthServiceKeysProvider>() is ExternalKeysProvider &&
               serviceProvider.GetService<CustodianHeldKeys>() is null
            ? ValidateOptionsResult.Fail(ExternalKeysProvider.NoKeyNamed)
            : ValidateOptionsResult.Success;
    }

    /// <summary>
    /// Whether the keys come from the settings: the resolved provider is the library's static one and no custodian
    /// is wired.
    /// </summary>
    internal static bool KeysComeFromSettings(IServiceProvider serviceProvider)
        => serviceProvider.GetService<IAuthServiceKeysProvider>() is OidcOptionsKeysProvider &&
           serviceProvider.GetService<IKeyCustodian>() is null;

#pragma warning disable ABXMT001
    private static string NoTenantSigningKey
        => "No signing key is declared, so the tenant cannot issue a single token and publishes an empty JWKS. " +
           $"Supply at least one JWK with a private part in {nameof(TenantDefinition)}." +
           $"{nameof(TenantDefinition.SigningKeys)}, or have the keys held by a custodian or minted by the server.";
#pragma warning restore ABXMT001

    private static string NoSigningKey
        => $"No signing key is configured, so the server cannot issue a single token and publishes an empty JWKS. " +
           $"The library does not generate keys: supply at least one JWK with a private part in " +
           $"{nameof(OidcOptions)}.{nameof(OidcOptions.SigningKeys)}, or register your own " +
           $"{nameof(IAuthServiceKeysProvider)} that reads keys from where your deployment keeps them " +
           "(the Vault and Azure key packages ship such providers).";
}
