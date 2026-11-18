// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The fields the login page posts back.
/// </summary>
/// <param name="Email">The email the user typed.</param>
/// <param name="Password">The password the user typed.</param>
/// <param name="RequestUri">The pending authorization request the form carries back.</param>
/// <param name="Action">Which button was pressed: <c>allow</c> or <c>deny</c>.</param>
public sealed record LoginForm(
    [FromForm(Name = "email")] string Email,
    [FromForm(Name = "password")] string Password,
    [FromForm(Name = "requestUri")] string RequestUri,
    [FromForm(Name = "action")] string? Action);
