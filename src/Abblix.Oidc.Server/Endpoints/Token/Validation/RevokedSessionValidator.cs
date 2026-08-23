// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Revocation;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Refuses a grant whose authentication session a revocation cutoff has caught.
/// </summary>
/// <remarks>
/// The third place a revocation has to be read, and the only one that sees this case. The token side compares
/// issue times, and every token minted at redemption is new, so it passes. The authorization endpoint judged
/// this session when the grant was created and does not see it again. What is left is the interval between
/// authorizing and redeeming - a minute for an authorization code by default, far longer for a device code or
/// a back-channel request - and a grant redeemed inside it founds a refresh family that stays past the cutoff
/// for its whole life, because rotation carries the first issue time forward.
/// <para>
/// A validator rather than a step in the processor, because the processor runs downstream of an irreversible
/// spend: <see cref="AuthorizationCodeReusePreventingDecorator"/> removes the authorization code before
/// delegating, so a refusal there would burn a code the request never earned. Validation happens first.
/// </para>
/// <para>
/// It asks only about grants that carry a session from an earlier request. The remaining grant types build
/// their session during this one - a client credentials, jwt-bearer or token exchange request stamps
/// <c>AuthenticationTime</c> from the current clock and generates the session identifier on the spot - so no
/// cutoff can predate it, and asking would be two store reads that cannot answer yes. It would also put a
/// subject from somebody else's namespace against our cutoffs: under client credentials the subject is the
/// client identifier, and under the assertion grants it belongs to a federated issuer.
/// </para>
/// </remarks>
/// <param name="cutoffChecker">Decides whether a cutoff refuses the session behind the grant.</param>
public class RevokedSessionValidator(IRevocationCutoffChecker cutoffChecker) : ITokenContextValidator
{
    /// <summary>
    /// The grant types whose session was authenticated before this request and can therefore have been
    /// revoked since.
    /// </summary>
    /// <remarks>
    /// Named rather than derived, because the alternative is to ask whether an authentication time is
    /// "recent", which is the same clock comparison this validator exists to make and would answer itself.
    /// A grant type added later is absent from this set and is not asked about; the test walking the
    /// registered handlers is what makes that a decision rather than an omission.
    /// </remarks>
    private static readonly HashSet<string> RedeemsAnEarlierSession =
    [
        GrantTypes.AuthorizationCode,
        GrantTypes.RefreshToken,
        GrantTypes.DeviceAuthorization,
        GrantTypes.Ciba,
    ];

    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        if (context.Request.GrantType is not { } grantType || !RedeemsAnEarlierSession.Contains(grantType))
            return null;

        if (!await cutoffChecker.IsSessionRefusedAsync(context.AuthorizedGrant.AuthSession))
            return null;

        // RFC 6749 Section 5.2 names this case in the definition of the code: the grant is "invalid,
        // expired, revoked, does not match the redirection URI used in the authorization request, or was
        // issued to another client".
        return new OidcError(
            ErrorCodes.InvalidGrant,
            "The session this grant was authorized from has been revoked.");
    }
}
