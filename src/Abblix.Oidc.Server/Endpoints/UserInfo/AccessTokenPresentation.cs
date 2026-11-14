// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// How a UserInfo request presented its access token.
/// </summary>
public static class AccessTokenPresentation
{
    /// <summary>
    /// The scheme the request presented its access token with, read from the request alone so that every refusal of
    /// it, whichever stage makes one, is answered for the same scheme (RFC 9449 section 7.2: "If the mechanism used to
    /// attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information").
    /// </summary>
    /// <returns>
    /// <see cref="AccessTokenScheme.Bearer"/> for the <c>Authorization: Bearer</c> header or an <c>access_token</c>
    /// parameter, each one of the "three methods of sending bearer access tokens" of RFC 6750 section 2, so the header
    /// and a parameter together still name one scheme; <see cref="AccessTokenScheme.DPoP"/> for the
    /// <c>Authorization: DPoP</c> header alone; null for that header beside a parameter, two schemes at once
    /// (section 7.2, Figure 19), and for a request presenting no token in a scheme the endpoint speaks.
    /// </returns>
    public static AccessTokenScheme? SchemeOf(UserInfoRequest request, ClientRequest clientRequest)
    {
        var header = clientRequest.AuthorizationHeader;
        var parameter = request.AccessToken;

        if (header.HasScheme(TokenTypes.DPoP))
            return parameter is null ? AccessTokenScheme.DPoP : null;

        if (header.HasScheme(TokenTypes.Bearer) || parameter is not null)
            return AccessTokenScheme.Bearer;

        return null;
    }
}
