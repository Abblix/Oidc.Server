// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// The refusal of a request the license does not cover, carrying which of its terms refused it so the endpoint
/// serving the request can count it.
/// </summary>
/// <param name="reason">The term that refused the request, one of
/// <see cref="Telemetry.LicenseRefusalReasons"/>.</param>
internal sealed class LicenseViolationException(string reason)
    : InvalidOperationException("The license terms violation detected")
{
    /// <summary>
    /// The term that refused the request, one of <see cref="Telemetry.LicenseRefusalReasons"/>.
    /// </summary>
    public string Reason { get; } = reason;
}
