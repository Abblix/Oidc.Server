// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Oidc;

/// <summary>
/// Values of the <c>token_type_hint</c> parameter of a revocation or introspection request, as RFC 7009
/// section 2.1 defines them. The hint only helps the server find the token, so a server may ignore it.
/// </summary>
public static class TokenTypeHints
{
    /// <summary>An access token (RFC 6749 section 1.4).</summary>
    public const string AccessToken = "access_token";

    /// <summary>A refresh token (RFC 6749 section 1.5).</summary>
    public const string RefreshToken = "refresh_token";
}
