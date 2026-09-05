// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value travels on the wire as an integer number of seconds while the model
/// exposes it as a <see cref="TimeSpan"/> - e.g. the OIDC <c>max_age</c> and CIBA
/// <c>requested_expiry</c> parameters. Purely semantic: it names the wire format and leaves
/// the parsing mechanism to the transport layer.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class TotalSecondsAttribute : Attribute;
