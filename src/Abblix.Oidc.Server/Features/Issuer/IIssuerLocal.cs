// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// A value a service builds once for each issuer it serves, such as a registry built from the issuer's
/// <see cref="IIssuerSettings"/>.
/// </summary>
/// <remarks>
/// Each service that asks for one gets its own, so two services keeping values of the same type never share them,
/// and the values last as long as that service does: one registered per request builds them for every request.
/// </remarks>
/// <typeparam name="T">The type of the value.</typeparam>
public interface IIssuerLocal<T> where T : class
{
    /// <summary>
    /// The value for the issuer serving the request, built by <paramref name="create"/> the first time that issuer
    /// asks for it.
    /// </summary>
    /// <remarks>
    /// <paramref name="create"/> runs while that issuer is serving, so the settings it reads are the issuer's.
    /// </remarks>
    T GetOrCreate(Func<T> create);
}
