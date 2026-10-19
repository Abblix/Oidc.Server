// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Resolves a template carrying route tokens, such as <c>[route:api?~/api]</c>, into the path it stands for, from
/// the configuration section <see cref="ConfigurableRoutesExtensions.ConfigureRoutes"/> was given and with the token
/// prefix it was given.
/// </summary>
/// <remarks>
/// For an address that is not a controller route, so the host's routing cannot build it: a fallback endpoint under
/// a configurable path, or a page address published in a document. Registered by
/// <see cref="ConfigurableRoutesExtensions.ConfigureRoutes"/>, which resolves the host's attribute route templates
/// the same way.
/// </remarks>
public interface IRouteTemplateResolver
{
    /// <summary>
    /// Replaces every token in <paramref name="template"/> with the value the section holds under its name, or with
    /// its fallback where the section is silent, and reads a leading <c>~/</c> as <c>/</c>.
    /// </summary>
    /// <param name="template">The template, such as <c>[route:passkeys_enroll?~/manage/passkeys]</c>.</param>
    /// <returns>The path, such as <c>/manage/passkeys</c>; a template with no token comes back as it was, but for
    /// its leading <c>~/</c>.</returns>
    /// <exception cref="InvalidOperationException">A token refers back to itself, has neither a value nor a
    /// fallback, or resolves to a path starting with <c>~</c> not followed by <c>/</c>.</exception>
    string Resolve(string template);
}
