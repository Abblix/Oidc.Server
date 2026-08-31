// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for initiating user authentication on a device in the context of a backchannel authentication
/// flow. This interface is responsible for handling the initiation of the authentication process for the end-user
/// on their device, based on a validated backchannel authentication request.
/// </summary>
/// <remarks>
/// <para><strong>Implementation Guide:</strong></para>
/// <para>
/// Implement this interface to integrate your authentication mechanism with CIBA. Your implementation should:
/// </para>
/// <list type="bullet">
///   <item>Send authentication request to user's device (push notification, SMS, email, etc.)</item>
///   <item>Display binding_message if present in the request</item>
///   <item>Handle user approval/denial asynchronously</item>
///   <item>Update authentication status when user responds</item>
/// </list>
///
/// <para><strong>Example Implementation with Ping Mode Support:</strong></para>
/// <code>
/// public class MyUserDeviceAuthenticationHandler : IUserDeviceAuthenticationHandler
/// {
///     private readonly IBackChannelRequestStorage _storage;
///     private readonly IAuthenticationCompletionHandler _completion;
///     private readonly ISessionIdGenerator _sessionIdGenerator;
///     private readonly IMyPushNotificationService _pushService;
///
///     public async Task&lt;Result&lt;AuthSession, OidcError&gt;&gt; InitiateAuthenticationAsync(
///         ValidBackChannelAuthenticationRequest request)
///     {
///         // Extract user hint and send authentication request to their device
///         var userIdentifier = ExtractUserIdentifier(request);
///         var bindingMessage = request.Model.BindingMessage;
///
///         // Send push notification to user's device
///         await _pushService.SendAuthRequestAsync(userIdentifier, bindingMessage);
///
///         // Return pending - authentication completes asynchronously
///         // User will approve/deny on their device
///         return new OidcError(ErrorCodes.AuthorizationPending, "Waiting for user approval");
///     }
///
///     // Called when user approves on their device
///     public async Task OnUserApprovedAsync(string authReqId, string userId)
///     {
///         // Retrieve the stored authentication request
///         var storedRequest = await _storage.TryGetAsync(authReqId);
///         if (storedRequest == null) return;
///
///         // Create authenticated session
///         var authSession = new AuthSession(
///             userId,
///             SessionId: _sessionIdGenerator.GenerateSessionId(),
///             AuthenticationTime: DateTimeOffset.UtcNow,
///             IdentityProvider: "local");
///
///         // Carry the end user's answer on the grant. AuthorizedGrant is a positional member of the
///         // record, so it is init-only and a `with` expression is how it is replaced; the copy carries
///         // every other member unchanged.
///         //
///         // Nothing needs to touch Status: the completion handler decides from the STORED record
///         // whether this request may still be answered, and sets Authenticated itself when it may. A
///         // host that does set it on its own copy changes nothing either way.
///         var authenticated = storedRequest with
///         {
///             AuthorizedGrant = new AuthorizedGrant(authSession, storedRequest.AuthorizedGrant.Context),
///         };
///
///         // Completion selects the mode-specific handler from the client's registered delivery mode
///         // (PollModeCompletionHandler, PingModeCompletionHandler or PushModeCompletionHandler) and
///         // marks the request authenticated itself - the caller does not set the status.
///         await _completion.CompleteAsync(
///             authReqId,
///             authenticated,
///             TimeSpan.FromMinutes(5));
///     }
///
///     // Called when user denies on their device
///     public async Task OnUserDeniedAsync(string authReqId)
///     {
///         var storedRequest = await _storage.TryGetAsync(authReqId);
///         if (storedRequest == null) return;
///
///         storedRequest.Status = BackChannelAuthenticationStatus.Denied;
///         await _storage.UpdateAsync(authReqId, storedRequest, TimeSpan.FromMinutes(5));
///     }
/// }
/// </code>
///
/// <para><strong>Token Delivery Modes:</strong></para>
/// <para>
/// The <see cref="IAuthenticationCompletionHandler.CompleteAsync"/> method automatically handles
/// mode-specific behavior based on the client's registered <c>backchannel_token_delivery_mode</c>:
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>Poll Mode:</strong> Stores the authenticated request in
///     <see cref="IBackChannelRequestStorage"/>. No token exists yet - the client polls the token
///     endpoint with its <c>auth_req_id</c>, and the tokens are minted there when it redeems.
///   </item>
///   <item>
///     <strong>Ping Mode:</strong> Stores the authenticated request as poll mode does, then sends an
///     HTTP POST notification via <see cref="INotificationDeliveryService"/> to the client's
///     <c>client_notification_endpoint</c> carrying the <c>auth_req_id</c>. The tokens are minted at
///     the token endpoint when the client redeems, exactly as in poll mode.
///   </item>
///   <item>
///     <strong>Push Mode:</strong> Generates tokens via <see cref="ITokenRequestProcessor"/> and delivers
///     them directly via <see cref="INotificationDeliveryService"/> to the client's
///     <c>client_notification_endpoint</c>. This is the only mode where the tokens exist before the
///     client asks for them, and the request is removed once they are delivered, because a push client
///     never comes to the token endpoint. CIBA Core 1.0 does not require that removal - it says nothing
///     about what the OP keeps - so it is this library's choice.
///   </item>
/// </list>
///
/// <para><strong>Partial consent (RFC 9396 authorization_details):</strong></para>
/// <para>
/// The grant carried on the stored request is what will be issued, so an end user who approved part of
/// what the client asked for is expressed by replacing its <c>AuthorizationContext</c> before completing:
/// keep the entries they agreed to, drop the ones they refused, and hand the result to
/// <see cref="IAuthenticationCompletionHandler.CompleteAsync"/>. The example above copies the context
/// unchanged, which is the "they agreed to all of it" case.
/// </para>
/// <para>
/// This is the only moment such an answer exists. <see cref="IUserDeviceAuthenticationHandler.InitiateAuthenticationAsync"/>
/// runs before the end user has seen anything - the session it returns names who is about to be reached,
/// and the request is stored pending either way - so there is nothing to narrow there.
/// </para>
/// <para>
/// Narrowing is yours to decide; widening is refused. Completion compares the grant's
/// <c>authorization_details</c> types against what the client actually sent, and a type the request never
/// carried denies the request rather than issuing it. RFC 9396 §7 has the server return what was granted,
/// which is only meaningful while "granted" stays inside "requested".
/// </para>
///
/// <para><strong>Additional Key Points:</strong></para>
/// <list type="bullet">
///   <item><strong>Binding Message:</strong> Display request.Model.BindingMessage to user for transaction confirmation</item>
///   <item><strong>User Code:</strong> If request.Model.UserCode is present, require user to confirm it</item>
///   <item><strong>Authentication:</strong> All notifications use Bearer token from <c>client_notification_token</c></item>
/// </list>
///
/// <para><strong>Security contract - user_code verification (CIBA Core 1.0 §7.1):</strong></para>
/// <para>
/// The library validates only the <em>presence</em> of <c>user_code</c> when the provider and client
/// require it (see <see cref="Endpoints.BackChannelAuthentication.Validation.UserCodeValidator"/>); it
/// deliberately does not - and cannot - verify the code's <em>value</em>, because the secret is known
/// only to the end-user and the user's authentication device, which this handler owns. Your
/// implementation therefore <strong>MUST</strong> verify <c>request.Model.UserCode</c> against the
/// user's actual code as part of the device interaction, and <strong>MUST NOT</strong> return a
/// successful <see cref="AuthSession"/> unless that check passed. A wrong or absent code MUST resolve
/// to a failed <see cref="Result{TValue,TError}"/> (typically <c>access_denied</c>).
/// Treating presence-validation as sufficient leaves the code unenforced and defeats its purpose.
/// </para>
/// </remarks>
public interface IUserDeviceAuthenticationHandler
{
    /// <summary>
    /// Initiates the authentication process for the user on their device, based on a validated backchannel
    /// authentication request.
    /// This may involve sending a notification to the user's device, starting an out-of-band
    /// authentication process, or performing other steps required to authenticate the user asynchronously.
    /// </summary>
    /// <param name="request">The validated backchannel authentication request containing user and client information
    /// required to initiate the authentication process.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation to initiate the authentication process.
    /// </returns>
    Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(ValidBackChannelAuthenticationRequest request);
}
