// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails at startup on a revocation setting that would let a revocation report success and do nothing.
/// </summary>
/// <remarks>
/// A revocation is one record with an expiry. At zero or below, the record expires as it is written, so
/// <c>RevokeSubjectAsync</c> returns successfully and the tokens it was called about keep working - a
/// security control that reports success and does nothing, which is the shape that gets discovered by an
/// incident rather than by a test.
/// <para>
/// Only the value that can never work is rejected. A value that is merely too short for a deployment's
/// longest-lived refresh token cannot be detected here: token lifetimes are per client and the client store
/// is not enumerable, so nothing at startup knows what the longest one is.
/// </para>
/// </remarks>
public sealed class RevocationRetentionOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.RevocationCutoffRetention <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.RevocationCutoffRetention)} is {options.RevocationCutoffRetention}, so every " +
                "revocation record would expire as it is written and no revocation would ever take effect. " +
                "Set it to at least the longest refresh token lifetime any client is configured with.");
        }

        // A negative tolerance narrows the cutoff instead of widening it, so tokens issued before a
        // revocation would survive it - the same silent nothing, reached from the other side.
        if (options.RevocationCutoffSkew < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.RevocationCutoffSkew)} is {options.RevocationCutoffSkew}. A negative " +
                "tolerance moves the cutoff backwards, so tokens issued before a revocation would pass it. " +
                "Use zero to allow none, or a positive value covering the clock difference between instances.");
        }

        return ValidateOptionsResult.Success;
    }
}
