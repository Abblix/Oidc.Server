// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// The request feature carrying the refusal of a client registration or update body decided before the body is bound,
/// a body of another media type or one over the bound: <see cref="RefusesClientMetadataAfterTheTokenAttribute"/>
/// answers it once the token is judged.
/// </summary>
/// <param name="Result">The refusal.</param>
internal sealed record ClientMetadataRefusal(ActionResult Result);
