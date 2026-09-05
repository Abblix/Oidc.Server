// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.MinimalApi.Attributes;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// The token endpoint request, bound from the posted <c>application/x-www-form-urlencoded</c> body. The bound
/// properties, <c>BindAsync</c> and the projection onto the core model are generated from
/// <see cref="Core.TokenRequest"/> by the Minimal API model source generator.
/// </summary>
[GeneratedFrom(typeof(Core.TokenRequest))]
public partial record TokenRequest;
