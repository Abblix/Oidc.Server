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
/// The stream store the host registered, kept under a key of its own as the store every tenant shares, while the
/// unkeyed registration answers with the store of the tenant being served.
/// </summary>
/// <param name="inner">The store the host registered.</param>
internal sealed class SharedStreamStore(IStreamStore inner) : ForwardingStreamStore(inner);
