// Abblix OIDC Server Library
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
///     private readonly IBackChannelAuthenticationStorage _storage;
///     private readonly IBackChannelAuthenticationNotifier _notifier;
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
///             sessionId: _sessionIdGenerator.GenerateSessionId(),
///             authenticationTime: DateTimeOffset.UtcNow,
///             identityProvider: "local");
///
///         // Update request with authenticated status
///         storedRequest.Status = BackChannelAuthenticationStatus.Authenticated;
///         storedRequest.AuthorizedGrant = new AuthorizedGrant(authSession, storedRequest.AuthorizedGrant.Context);
///
///         // Notify completion - automatically selects and delegates to the appropriate
///         // mode-specific notifier (PollModeNotifier, PingModeNotifier, or PushModeNotifier)
///         await _notifier.NotifyAuthenticationCompleteAsync(
///             authReqId,
///             storedRequest,
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
/// The <see cref="IBackChannelAuthenticationNotifier.NotifyAuthenticationCompleteAsync"/> method automatically handles
/// mode-specific behavior based on the client's registered <c>backchannel_token_delivery_mode</c>:
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>Poll Mode:</strong> Stores tokens in <see cref="IBackChannelAuthenticationStorage"/>.
///     Client polls the token endpoint with <c>auth_req_id</c> until tokens are ready.
///   </item>
///   <item>
///     <strong>Ping Mode:</strong> Stores tokens and sends HTTP POST notification via
///     <see cref="IBackChannelNotificationService"/> to the client's <c>client_notification_endpoint</c>
///     with the <c>auth_req_id</c>. Client then retrieves tokens from the token endpoint.
///   </item>
///   <item>
///     <strong>Push Mode:</strong> Generates tokens via <see cref="ITokenRequestProcessor"/> and delivers
///     them directly via <see cref="IBackChannelTokenDeliveryService"/> to the client's
///     <c>client_notification_endpoint</c>. Tokens are removed from storage after successful delivery
///     per CIBA specification section 10.3.1.
///   </item>
/// </list>
///
/// <para><strong>Additional Key Points:</strong></para>
/// <list type="bullet">
///   <item><strong>Binding Message:</strong> Display request.Model.BindingMessage to user for transaction confirmation</item>
///   <item><strong>User Code:</strong> If request.Model.UserCode is present, require user to confirm it</item>
///   <item><strong>Authentication:</strong> All notifications use Bearer token from <c>client_notification_token</c></item>
/// </list>
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
