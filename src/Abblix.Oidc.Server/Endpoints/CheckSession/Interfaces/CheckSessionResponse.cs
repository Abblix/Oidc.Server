// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;

/// <summary>
/// Represents the response to a check session request in OpenID Connect Session Management.
/// This record contains the necessary information to ascertain the current state of a user session.
/// </summary>
/// <param name="HtmlContent">The HTML content to be rendered, typically used in an iframe for session checking.</param>
/// <param name="CacheKey">An object that represents a cache key, used for optimizing session state checks.
/// It serves as a key for caching the response to reduce frequent reevaluation when the session state is expected
/// to remain unchanged for an extended period, enhancing performance.</param>
public record CheckSessionResponse(string HtmlContent, object CacheKey);
