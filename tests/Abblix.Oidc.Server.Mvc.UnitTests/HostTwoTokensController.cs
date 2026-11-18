// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>A host controller whose route carries two version 2.4 tokens.</summary>
[Route("[route:First?a]/[route:Second?b]")]
public sealed class HostTwoTokensController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();
}
