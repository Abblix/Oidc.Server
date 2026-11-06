// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Waits at the token endpoint for a grant whose user has not finished authorizing it yet.
/// </summary>
/// <remarks>
/// Two specifications describe this waiting in the same words, because the second copied the first: RFC 8628
/// section 3.5 for a device, and CIBA section 11 for a request made on a user's behalf from elsewhere. The
/// interval, the meaning of <c>authorization_pending</c>, the five seconds added by <c>slow_down</c> and the
/// instruction to stop on anything else are identical, and only the parameter carrying the identifier
/// differs. Kept in one place so a correction reaches both flows: two copies of a rule about how often to
/// ask a stranger's server is exactly the pair that drifts unnoticed, since the flow that drifts still works
/// and merely misbehaves.
/// </remarks>
/// <param name="timeProvider">Measures the waiting, so a test does not have to sit through it.</param>
internal sealed class GrantPoller(TimeProvider timeProvider)
{
    /// <summary>
    /// What both specifications add to the interval each time the provider answers <c>slow_down</c>.
    /// </summary>
    /// <remarks>
    /// RFC 8628 section 3.5 says "increased by 5 seconds"; CIBA section 11 says "increased by at least five
    /// seconds", which permits more and requires no less. Five satisfies both.
    /// </remarks>
    private static readonly TimeSpan SlowDownIncrement = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Repeats <paramref name="attempt"/> on the provider's terms until it yields tokens, is refused for
    /// good, or the grant's own lifetime runs out.
    /// </summary>
    /// <param name="interval">How long to wait between attempts, as the provider asked.</param>
    /// <param name="lifetime">How long the grant lasts, as the provider stated.</param>
    /// <param name="attempt">One try at redeeming it.</param>
    /// <param name="expiredMessage">What to say when the lifetime runs out first.</param>
    /// <param name="cancellationToken">Stops the waiting.</param>
    public async Task<TokenResponse> PollAsync(
        TimeSpan interval,
        TimeSpan lifetime,
        Func<CancellationToken, Task<TokenResponse>> attempt,
        string expiredMessage,
        CancellationToken cancellationToken)
    {
        // Read once, so a grant whose user never answers stops on its own rather than polling until
        // something else stops it. Both specifications have the provider answer expired_token, and neither
        // flow depends on it arriving: a provider that keeps saying authorization_pending past the lifetime
        // it stated would otherwise be polled for as long as the client stays switched on.
        var deadline = timeProvider.GetUtcNow() + lifetime;

        while (true)
        {
            // Waiting first, not last: both specifications say to wait before each new request, the first
            // one included, and the user has had no time at all at the moment the grant was handed over.
            // A provider is entitled to answer slow_down to a request that came sooner, and ours does.
            await Task.Delay(interval, timeProvider, cancellationToken);

            if (deadline <= timeProvider.GetUtcNow())
                throw new TokenRequestException(expiredMessage, TokenErrorCodes.ExpiredToken, null);

            try
            {
                return await attempt(cancellationToken);
            }
            catch (TokenRequestException refusal) when (refusal.Error == TokenErrorCodes.SlowDown)
            {
                // The increase is kept rather than applied to the next wait alone: it is "for this and all
                // subsequent requests". A client that widened the gap once and then went back would look
                // right on the next attempt and be asking too often again by the one after.
                interval += SlowDownIncrement;
            }
            catch (TokenRequestException refusal) when (refusal.Error == TokenErrorCodes.AuthorizationPending)
            {
                // The user is still deciding. Every other refusal, denial and expiry included, is final and
                // travels out of here untouched: a client receiving any other error must stop polling.
            }
        }
    }
}
