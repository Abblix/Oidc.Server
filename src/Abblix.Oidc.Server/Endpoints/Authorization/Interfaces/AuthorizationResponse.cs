// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

/// <summary>
/// Represents the response to an authorization request.
/// This abstract record serves as a base for specific authorization response
/// implementations. It should be inherited by classes that define the detailed
/// structure and behavior of different types of authorization responses.
/// </summary>
public abstract record AuthorizationResponse(AuthorizationRequest Model)
{
    /// <summary>
    /// Wire-level parameter names returned to the client by the authorization endpoint (via query,
    /// fragment, form_post, or - under JARM - as claims inside the single <c>response</c> JWT). Shared by
    /// the core response encoder and the MVC serialization DTO so the two never drift.
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>state</c> value echoed back verbatim to bind the response to the request
        /// (OAuth 2.0 section 4.1.2).</summary>
        public const string State = "state";

        /// <summary>The <c>code</c> authorization code returned by the Authorization Code Flow
        /// (OAuth 2.0 section 4.1.2).</summary>
        public const string Code = "code";

        /// <summary>The <c>token_type</c> of the issued access token (OAuth 2.0 section 4.2.2).</summary>
        public const string TokenType = "token_type";

        /// <summary>The <c>access_token</c> issued directly by the Implicit/Hybrid Flow
        /// (OAuth 2.0 section 4.2.2).</summary>
        public const string AccessToken = "access_token";

        /// <summary>The <c>expires_in</c> access-token lifetime in seconds (OAuth 2.0 section 4.2.2).</summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>The <c>id_token</c> issued by the Implicit/Hybrid Flow (OIDC Core section 3.2.2.5).</summary>
        public const string IdToken = "id_token";

        /// <summary>The <c>error</c> code identifying the failure (OAuth 2.0 section 4.1.2.1).</summary>
        public const string Error = "error";

        /// <summary>The <c>error_description</c> human-readable failure detail (OAuth 2.0 section 4.1.2.1).</summary>
        public const string ErrorDescription = "error_description";

        /// <summary>The <c>error_uri</c> pointing to documentation about the error (OAuth 2.0 section 4.1.2.1).</summary>
        public const string ErrorUri = "error_uri";

        /// <summary>The <c>scope</c> granted when it differs from the requested scope (OAuth 2.0 section 3.3).</summary>
        public const string Scope = "scope";

        /// <summary>The <c>session_state</c> value tracking the End-User session (OIDC Session Management
        /// section 3).</summary>
        public const string SessionState = "session_state";

        /// <summary>The <c>iss</c> issuer identifier authenticating the response source (RFC 9207).</summary>
        public const string Issuer = "iss";

        /// <summary>The <c>response</c> JWT carrying every other parameter as claims under JARM.</summary>
        public const string Response = "response";
    }
};
