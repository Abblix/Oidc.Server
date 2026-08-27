// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

public partial class DeviceAuthorizationStorage
{
    /// <summary>
    /// The only report a dangling user-code index ever produces.
    /// </summary>
    /// <remarks>
    /// The key is named because it is what an operator would search for or delete; it is a derived
    /// storage key rather than the user code itself, and it points at a request that is already gone.
    /// Warning rather than error: the device code was consumed and the caller was answered, so nothing
    /// downstream is waiting on this.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemoved,
        Level = LogLevel.Warning,
        Message = "The device code was consumed, but its user-code index at {UserCodeKey} could not be " +
                  "removed. The entry points at a request that no longer exists and expires on its own; " +
                  "the caller was told it took the code, which it did.")]
    private partial void LogUserCodeIndexNotRemoved(Exception exception, string UserCodeKey);
}
