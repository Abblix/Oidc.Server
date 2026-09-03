// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Validates that every statically-configured client whose effective profile mandates a control
/// bundle has a configuration that can satisfy it, failing loudly the first time
/// <see cref="OidcOptions"/> is resolved rather than letting a contradiction surface as a per-request
/// rejection at runtime. A no-op for deployments that select no profile, so existing configurations
/// are unaffected.
/// </summary>
public class OidcOptionsSecurityProfileValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new List<string>();

        // A profile that removes a control without the controls that replace it is a defect in this
        // library rather than in the host's configuration, so it is checked here, where startup can
        // still refuse, instead of being left to whoever reviews the next profile.
        failures.AddRange(SecurityProfileRequirements.FindUnreplacedRelaxations());

        // A profile is an enum, and the configuration binder does not check that a value it binds is
        // one the enum defines: a name it does not know throws while a NUMBER outside the range is
        // bound as it stands. Nothing downstream can serve such a value, so it is named here, at
        // startup - the alternative is that the deployment starts and every endpoint requiring a
        // client answers 500 instead.
        failures.AddRange(UndefinedProfile(options.DefaultSecurityProfile, "DefaultSecurityProfile"));

        foreach (var client in options.Clients)
        {
            if (client.SecurityProfile is { } clientProfile)
            {
                var undefined = UndefinedProfile(clientProfile, $"Client '{client.ClientId}'");
                if (undefined.Count > 0)
                {
                    failures.AddRange(undefined);
                    continue;
                }
            }

            var effectiveProfile = client.SecurityProfile ?? options.DefaultSecurityProfile;

            foreach (var violation in
                     SecurityProfileConsistency.FindViolations(
                         client.EffectiveResponseTypes,
                         client.TokenEndpointAuthMethod,
                         effectiveProfile))
            {
                failures.Add($"Client '{client.ClientId}': {violation}.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>
    /// Names a profile value the enum does not define, as the single-element list the caller adds to
    /// its failures. Empty for a defined value, which is what makes it usable as a guard.
    /// </summary>
    private static IReadOnlyList<string> UndefinedProfile(ClientSecurityProfile profile, string where)
        => Enum.IsDefined(profile)
            ? []
            : [$"{where}: {(int)profile} is not a security profile this server defines."];
}
