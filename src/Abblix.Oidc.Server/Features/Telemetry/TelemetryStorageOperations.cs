// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The values of <see cref="TelemetryTags.StorageOperation"/>: the operations of the server's entity storage.
/// </summary>
public static class TelemetryStorageOperations
{
    /// <summary>
    /// Reading an entry, removing it as it is read or not.
    /// </summary>
    public const string Get = "get";

    /// <summary>
    /// Writing an entry.
    /// </summary>
    public const string Set = "set";

    /// <summary>
    /// Writing an entry only where none is.
    /// </summary>
    public const string SetIfAbsent = "set_if_absent";

    /// <summary>
    /// Removing an entry.
    /// </summary>
    public const string Remove = "remove";
}
