// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The streams a tenant declares, as the transmitter being built for it serves them.
/// </summary>
/// <param name="Streams">The declared streams.</param>
/// <param name="IsInstalled">Whether the transmitter being built is still the one its creation is served, since a
/// store of declared streams another replaced writes nothing more.</param>
/// <param name="Served">The tenant's streams, read and written through the transmitter the tenant is served when each
/// call is made.</param>
internal sealed record TenantStreamDeclaration(
    IReadOnlyList<ConfiguredStream> Streams,
    Func<bool> IsInstalled,
    IStreamStore Served);
