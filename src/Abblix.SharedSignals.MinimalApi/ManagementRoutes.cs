// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The route segments of the management surface, single-sourced because the configuration
/// document must advertise exactly what is mapped.
/// </summary>
internal static class ManagementRoutes
{
    internal const string Stream = "/stream";
    internal const string Status = "/status";
    internal const string AddSubject = "/subjects:add";
    internal const string RemoveSubject = "/subjects:remove";
    internal const string Verify = "/verify";
    internal const string Poll = "/poll";
}
