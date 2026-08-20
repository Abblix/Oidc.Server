// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value travels on the wire as a JSON document carried inside a single parameter -
/// e.g. the OIDC <c>claims</c> parameter or RFC 9396 <c>authorization_details</c>. Purely semantic:
/// it names the wire format and leaves the parsing mechanism to the transport layer.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class JsonObjectAttribute : Attribute;
