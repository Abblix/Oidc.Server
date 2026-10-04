// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// The identity of a deployment that has no transmitter for the request, as a multi-tenant server for a request that
/// reached no tenant.
/// </summary>
internal sealed class NoTransmitter : ITransmitterIdentity
{
    public string Issuer => throw new InvalidOperationException("No transmitter serves this request.");

    public Uri? JwksUri => null;

    public Uri EndpointsBase => throw new InvalidOperationException("No transmitter serves this request.");

    public bool Serves => false;

    public string? ReceiverIssuer => null;
}
