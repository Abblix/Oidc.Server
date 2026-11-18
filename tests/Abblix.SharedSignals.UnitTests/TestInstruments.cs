// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.Metrics;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The transmitter's instruments for a test whose subject is not what they record.
/// </summary>
internal static class TestInstruments
{
    private static readonly IMeterFactory Meters =
        new ServiceCollection().AddMetrics().BuildServiceProvider().GetRequiredService<IMeterFactory>();

    public static SharedSignalsInstruments Create() => new(
        Meters,
        new OptionsTransmitterIdentity(new SharedSignalsTransmitterOptions { Issuer = "https://transmitter.example.com" }));
}
