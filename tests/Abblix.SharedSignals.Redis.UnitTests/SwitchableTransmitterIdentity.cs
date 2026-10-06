// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// An identity whose issuer the test changes between calls, the way a host answering as one issuer per tenant
/// changes it between requests.
/// </summary>
/// <param name="issuer">The issuer it answers with until the test changes it.</param>
internal sealed class SwitchableTransmitterIdentity(string issuer) : ITransmitterIdentity
{
    public string Issuer { get; set; } = issuer;

    public Uri? JwksUri => null;

    public Uri EndpointsBase => new(new Uri(Issuer).GetLeftPart(UriPartial.Authority));

    public bool Serves => true;

    public string? ReceiverIssuer => null;

    public string? TenantId => null;
}
