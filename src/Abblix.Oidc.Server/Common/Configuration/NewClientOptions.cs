// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Defaults used by the dynamic client registration endpoint when minting credentials for a newly
/// registered client: how its client identifier and client secret are generated and how long the
/// secret stays valid.
/// </summary>
public record NewClientOptions
{
    /// <summary>
    /// Generation parameters for the client identifier issued to a newly registered client.
    /// </summary>
    public ClientIdOptions ClientId { get; init; } = new();

    /// <summary>
    /// Generation parameters and lifetime policy for the client secret issued to a newly registered client.
    /// </summary>
    public ClientSecretOptions ClientSecret { get; init; } = new();
}
