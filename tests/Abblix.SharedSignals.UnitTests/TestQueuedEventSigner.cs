// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Signs a queued SET for a test whose subject is what is sent rather than how it is signed.
/// </summary>
/// <remarks>
/// The compact token it produces is "signed.{jti}", so a test can tell which event went out, and a queued item
/// that is already a compact token goes out exactly as it was queued.
/// </remarks>
internal static class TestQueuedEventSigner
{
    public static QueuedEventSigner Create(TimeProvider? clock = null)
        => new(new NamingSigner(), new OptionsTransmitterIdentity(new SharedSignalsTransmitterOptions { Issuer = "https://tr.example.com" }), clock);
}
