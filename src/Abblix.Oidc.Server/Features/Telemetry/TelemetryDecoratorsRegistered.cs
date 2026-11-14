// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The decorators already wrapping their service, so a registration method called again does not measure a call
/// twice.
/// </summary>
internal sealed class TelemetryDecoratorsRegistered
{
    /// <summary>
    /// The decorators registered.
    /// </summary>
    public HashSet<Type> Decorators { get; } = [];
}
