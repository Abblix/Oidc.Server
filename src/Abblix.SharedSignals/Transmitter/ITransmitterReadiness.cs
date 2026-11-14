// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Tells when the transmitter can be asked who it is for a request: a transmitter whose identity and parts depend on
/// something loaded at startup waits for it here.
/// </summary>
/// <remarks>
/// The transmitter's endpoints wait for it before anything of the transmitter is resolved for the request, so a
/// request arriving while that is still being loaded is answered as it is once it has loaded. A host registering
/// none waits for nothing.
/// </remarks>
public interface ITransmitterReadiness
{
    /// <summary>
    /// Completes once the transmitter can be asked who it is for a request.
    /// </summary>
    /// <param name="cancellationToken">Ends the wait, as when the request is aborted.</param>
    ValueTask WaitAsync(CancellationToken cancellationToken);
}
