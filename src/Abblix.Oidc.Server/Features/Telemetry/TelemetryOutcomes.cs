// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The values of <see cref="TelemetryTags.Outcome"/>.
/// </summary>
public static class TelemetryOutcomes
{
    /// <summary>
    /// The request was served.
    /// </summary>
    public const string Success = "success";

    /// <summary>
    /// The request was answered with a protocol error, named by <see cref="TelemetryTags.Error"/>.
    /// </summary>
    public const string Refused = "refused";

    /// <summary>
    /// The handling ended in an exception.
    /// </summary>
    public const string Failed = "failed";
}
