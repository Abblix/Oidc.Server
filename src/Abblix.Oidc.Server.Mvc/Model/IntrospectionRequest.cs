// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Attributes;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// The transport-bound counterpart of <see cref="Core.IntrospectionRequest"/> for the token
/// introspection endpoint (RFC 7662). All bound properties, validation attributes and the
/// projection back onto the core model are generated from the core type.
/// </summary>
[GeneratedFrom(typeof(Core.IntrospectionRequest))]
public partial record IntrospectionRequest;
