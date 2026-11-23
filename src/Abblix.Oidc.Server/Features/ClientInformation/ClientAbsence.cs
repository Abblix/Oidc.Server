// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The answer of <see cref="IClientInfoProvider"/> when a client identifier names no client the server serves.
/// </summary>
/// <param name="Reason">Why the identifier names no client.</param>
public sealed record ClientAbsence(ClientAbsenceReason Reason)
{
    /// <summary>
    /// No client is known under the identifier: what a store answers for an identifier it does not hold.
    /// </summary>
    public static ClientAbsence Unknown { get; } = new(ClientAbsenceReason.Unknown);

    /// <summary>
    /// The client's metadata document was had and refused.
    /// </summary>
    public static ClientAbsence Refused { get; } = new(ClientAbsenceReason.Refused);

    /// <summary>
    /// The client's metadata document could not be had for now, and no valid copy of it is held.
    /// </summary>
    public static ClientAbsence TemporarilyUnavailable { get; } = new(ClientAbsenceReason.TemporarilyUnavailable);
}
