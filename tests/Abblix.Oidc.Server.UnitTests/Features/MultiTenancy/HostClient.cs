// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

// A namespace of a host's own, outside the server's
namespace HostApplication.Clients;

/// <summary>A client type of a host's own, as a host keeping more about each client declares.</summary>
public sealed record HostClient(string ClientId) : ClientInfo(ClientId)
{
    public string? Department { get; set; }

    /// <summary>The client this one acts for, which may be the client itself.</summary>
    public HostClient? ActsFor { get; set; }
}
