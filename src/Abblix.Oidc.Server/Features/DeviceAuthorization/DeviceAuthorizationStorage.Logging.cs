// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

partial class DeviceAuthorizationStorage
{
    /// <summary>
    /// The only report a dangling user-code index ever produces.
    /// </summary>
    /// <remarks>
    /// The key is named because it is what an operator would search for or delete. It EMBEDS the user
    /// code - the factory builds it by interpolation - so this line writes the code in full; that is
    /// acceptable here and nowhere near free elsewhere, because the record it addressed is gone and the
    /// code is spent the moment this runs. Warning rather than error: the device code was consumed and
    /// the caller was answered, so nothing downstream is waiting on this.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.DeviceAuthorizationStorage.UserCodeIndexNotRemoved,
        Level = LogLevel.Warning,
        Message = "The device code was consumed, but its user-code index at {UserCodeKey} could not be " +
                  "removed. The entry points at a request that no longer exists and expires on its own; " +
                  "the caller was told it took the code, which it did.")]
    private partial void LogUserCodeIndexNotRemoved(Exception exception, string UserCodeKey);
}
