// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The name the server's traces are published under, which a host passes to its OpenTelemetry setup to receive them:
/// <c>AddOpenTelemetry().WithTracing(t =&gt; t.AddSource(OidcTelemetry.SourceName))</c>.
/// </summary>
/// <remarks>
/// The server records spans whether or not anything listens: a source nobody listens to starts no span and costs
/// nothing, so the host's subscription is the only switch.
/// </remarks>
public static class OidcTelemetry
{
    /// <summary>
    /// The name of the server's <see cref="ActivitySource"/>.
    /// </summary>
    public const string SourceName = "Abblix.Oidc.Server";

    /// <summary>
    /// The source the server starts its spans from, versioned with the assembly.
    /// </summary>
    internal static readonly ActivitySource Source = new(
        SourceName,
        typeof(OidcTelemetry).Assembly.GetName().Version?.ToString());
}
