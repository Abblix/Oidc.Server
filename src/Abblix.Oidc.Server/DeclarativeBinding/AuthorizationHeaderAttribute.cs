// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.DeclarativeBinding;

/// <summary>
/// Declares that the value is the parsed HTTP <c>Authorization</c> request header - the scheme and
/// credentials used by transport-level client authentication such as <c>Basic</c> (RFC 7617) or
/// <c>Bearer</c> (RFC 6750). Purely semantic: it names the transport source and leaves the parsing
/// mechanism to the transport layer.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AuthorizationHeaderAttribute : Attribute;
