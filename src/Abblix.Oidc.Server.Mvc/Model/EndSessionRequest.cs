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
/// The transport-bound counterpart of <see cref="Core.EndSessionRequest"/> for the RP-initiated
/// logout endpoint, reachable via GET and POST. The bound properties, model binders resolved from
/// the core wire-format markers and the projection back onto the core model are generated from
/// the core type.
/// </summary>
/// <remarks>
/// A <c>post_logout_redirect_uri</c> sent with neither <c>id_token_hint</c> nor <c>client_id</c> is not refused
/// here: the logout is still allowed, and the end-session validation drops the address it cannot confirm, the same
/// on every host.
/// </remarks>
[GeneratedFrom(typeof(Core.EndSessionRequest), SupportsGet = true)]
public partial record EndSessionRequest;
