// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value travels on the wire as a single space-separated string while the model
/// exposes it as an array - e.g. the OAuth 2.0 <c>scope</c> and <c>acr_values</c> parameters.
/// Purely semantic: it names the wire format and leaves the parsing mechanism to the transport layer.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class SpaceSeparatedStringAttribute : Attribute;
