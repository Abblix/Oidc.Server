// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The decorators already wrapping their endpoint's handler, so a registration method called again does not wrap it
/// in a second span.
/// </summary>
internal sealed class EndpointSpansRegistered
{
    /// <summary>
    /// The decorators registered.
    /// </summary>
    public HashSet<Type> Decorators { get; } = [];
}
