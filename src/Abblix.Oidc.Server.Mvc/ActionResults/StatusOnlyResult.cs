// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Answers with a status code and no body at all.
/// </summary>
/// <remarks>
/// <see cref="StatusCodeResult"/> cannot be used where the body has to stay empty: it is an
/// <see cref="Microsoft.AspNetCore.Mvc.Infrastructure.IClientErrorActionResult"/>, so on a controller carrying
/// <see cref="ApiControllerAttribute"/> the framework replaces it with a synthesized
/// <see cref="ProblemDetails"/> body. The Minimal API adapter sends a status and nothing, and the two adapters
/// owe the same answer to the same request, so the refusals this library decides for itself go out through
/// this result instead.
/// </remarks>
/// <param name="statusCode">The status the response carries.</param>
internal sealed class StatusOnlyResult(int statusCode) : ActionResult
{
    /// <inheritdoc />
    public override void ExecuteResult(ActionContext context)
        => context.HttpContext.Response.StatusCode = statusCode;
}
