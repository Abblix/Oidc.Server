// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// A client dynamic registration added, with the identifier (<c>jti</c>) of the registration access token that
/// currently manages it through the client configuration endpoint (RFC 7592).
/// </summary>
/// <param name="ClientInfo">The registered client.</param>
/// <param name="RegistrationAccessTokenId">The identifier of the registration access token managing it.</param>
public record RegisteredClient(ClientInfo ClientInfo, string RegistrationAccessTokenId);
