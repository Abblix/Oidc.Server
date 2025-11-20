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
///     private readonly BackChannelAuthenticationNotifier _notifier;
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
///             sessionId: Guid.NewGuid().ToString(),
///             authenticationTime: DateTimeOffset.UtcNow,
///             identityProvider: "local");
///
///         // Update request with authenticated status
///         storedRequest.Status = BackChannelAuthenticationStatus.Authenticated;
///         storedRequest.AuthorizedGrant = new AuthorizedGrant(authSession, storedRequest.AuthorizedGrant.Context);
///
///         // Update storage and send ping notification if configured
///         // This automatically sends notification for ping mode clients
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
/// <para><strong>Key Points:</strong></para>
/// <list type="bullet">
///   <item><strong>Poll Mode:</strong> User polls token endpoint until authentication completes</item>
///   <item><strong>Ping Mode:</strong> BackChannelAuthenticationNotifier automatically sends HTTP notification when you call NotifyAuthenticationCompleteAsync</item>
///   <item><strong>Binding Message:</strong> Display request.Model.BindingMessage to user for transaction confirmation</item>
///   <item><strong>User Code:</strong> If request.Model.UserCode is present, require user to confirm it</item>
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
