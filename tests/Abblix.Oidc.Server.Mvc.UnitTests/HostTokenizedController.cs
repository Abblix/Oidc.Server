// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>A host controller whose route carries a version 2.4 token, as that version's documentation showed.</summary>
[Route("[route:ApiPrefix?v1]/users")]
public sealed class HostTokenizedController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();
}
