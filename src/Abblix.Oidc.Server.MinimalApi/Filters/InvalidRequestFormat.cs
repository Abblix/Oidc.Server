// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Filters;

/// <summary>
/// Endpoint metadata naming how <see cref="ValidationEndpointFilter"/> answers a request it refuses at that endpoint,
/// in place of the bare <c>invalid_request</c> it answers everywhere else.
/// </summary>
/// <param name="Format">Formats the refusal of the request.</param>
internal sealed record InvalidRequestFormat(Func<HttpContext, OidcError, Task<IResult>> Format);
