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
/// The authorization request a client pushes (RFC 9126), bound from the posted form only, as the MVC host binds it:
/// section 2.1 says "The client constructs the message body of an HTTP 'POST' request with parameters", so a value in
/// the query is not part of the request. The bound properties, <c>BindAsync</c> and the projection onto the core model
/// are generated from <see cref="Core.AuthorizationRequest"/> by the Minimal API model source generator.
/// </summary>
[GeneratedFrom(typeof(Core.AuthorizationRequest))]
public partial record PushedAuthorizationRequest;
