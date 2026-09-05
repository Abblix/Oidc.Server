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
/// The transport-bound counterpart of <see cref="Core.BackChannelAuthenticationRequest"/> for the
/// CIBA backchannel authentication endpoint. All bound properties, model binders resolved from
/// the core wire-format markers and the projection back onto the core model are generated from
/// the core type.
/// </summary>
[GeneratedFrom(typeof(Core.BackChannelAuthenticationRequest))]
public partial record BackChannelAuthenticationRequest;
