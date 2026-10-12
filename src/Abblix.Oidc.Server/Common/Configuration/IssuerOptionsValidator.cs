// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Issuer;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails at startup on a configured issuer that cannot be one: not an absolute URL, not https unless
/// <see cref="OidcOptions.AllowHttpIssuer"/> lets http through, or carrying a query or a fragment.
/// </summary>
/// <remarks>
/// Every token the server issues carries the issuer, so a wrong one is refused before the first token rather than
/// discovered by every relying party that rejects it. With no issuer configured the server takes it from each
/// request, and the library's endpoints serve only https.
/// </remarks>
public sealed class IssuerOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.Issuer is not { } issuer)
            return ValidateOptionsResult.Success;

        return IssuerIdentifier.Refusal(issuer, options.AllowHttpIssuer) is { } refusal
            ? ValidateOptionsResult.Fail($"{nameof(options.Issuer)} '{issuer.OriginalString}' {refusal}.")
            : ValidateOptionsResult.Success;
    }
}
