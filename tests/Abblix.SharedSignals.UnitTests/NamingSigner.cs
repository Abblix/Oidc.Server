// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Signs a SET as "signed.{jti}", for a test that measures which event went out rather than how it was signed.
/// </summary>
internal sealed class NamingSigner : ISecurityEventTokenSigner
{
    public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        => Task.FromResult($"signed.{token.JwtId}");
}
