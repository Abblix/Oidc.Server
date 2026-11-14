// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One pass over the push streams: what <see cref="PushDeliveryScheduler"/> runs at each tick.
/// </summary>
/// <remarks>
/// A seam of its own so a deployment whose streams are kept apart - one set per tenant - can run the pass once
/// for each set, by wrapping this one, without a timer of its own.
/// </remarks>
public interface IPushDeliverySweep
{
    /// <summary>
    /// Delivers what is pending on every enabled push stream this instance can claim.
    /// </summary>
    /// <param name="cancellationToken">Stops the pass.</param>
    Task SweepAsync(CancellationToken cancellationToken);
}
