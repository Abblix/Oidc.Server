// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The value of the one issuer a deployment without multi-tenancy serves.
/// </summary>
internal sealed class SingleIssuerLocal<T> : IIssuerLocal<T> where T : class
{
    private T? _value;

    /// <inheritdoc />
    public T GetOrCreate(Func<T> create) => LazyInitializer.EnsureInitialized(ref _value, create);
}
