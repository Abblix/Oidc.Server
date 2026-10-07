// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server



using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using static Abblix.Oidc.Server.Model.AuthorizationRequest;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Refuses a <c>display</c> value outside the set OpenID Connect Core 1.0, section 3.1.2.1, defines: <c>page</c>,
/// <c>popup</c>, <c>touch</c> and <c>wap</c>.
/// </summary>
/// <remarks>
/// The section lets a server either refuse a value it does not understand or ignore it; this one refuses, and does so
/// after the client and the redirect URI are validated, so the client is told at its redirect URI.
/// </remarks>
public class DisplayValidator : SyncAuthorizationContextValidatorBase
{
    private static readonly HashSet<string> Supported =
        new([DisplayModes.Page, DisplayModes.Popup, DisplayModes.Touch, DisplayModes.Wap], StringComparer.Ordinal);

    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        if (context.Request.Display is not { } display || Supported.Contains(display))
            return null;

        return context.InvalidRequest($"The {Parameters.Display} value is not supported.");
    }
}
