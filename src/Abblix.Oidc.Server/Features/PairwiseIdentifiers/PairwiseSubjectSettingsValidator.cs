// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.PairwiseIdentifiers;

/// <summary>
/// Fails loudly at startup when the configured seal key cannot key the pairwise seal, instead of letting the
/// first pairwise token request answer 500.
/// </summary>
/// <remarks>
/// <para>
/// The salt is the sole key material of the seal, and the two ways it goes wrong are both quiet. An absent
/// key leaves the settings carrying null: <c>required</c> is a rule of the compiler, and the configuration
/// binder assigns only the properties whose keys are present, so nothing is raised and nothing is set. A
/// present but unusable key - not base64, or too short - is refused where it is assigned, but only for an
/// instance somebody wrote in code.
/// </para>
/// <para>
/// Downstream, neither is loud either: <see cref="SubjectTypeConverter"/> treats settings it cannot use as
/// pairwise not being configured, while discovery goes on advertising <c>pairwise</c> as a supported subject
/// type. So a client registered for it is accepted and fails at the token endpoint.
/// </para>
/// </remarks>
public sealed class PairwiseSubjectSettingsValidator : IValidateOptions<PairwiseSubjectSettings>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, PairwiseSubjectSettings options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return PairwiseSubjectSettings.SaltRefusal(options.Salt) is { } refusal
            ? ValidateOptionsResult.Fail(refusal)
            : ValidateOptionsResult.Success;
    }
}
