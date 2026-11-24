/*
 * Copyright (c) 2025 Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

using System.Security;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProtonVPN.Api.Contracts;
using ProtonVPN.Client.Contracts.Services.Browsing;
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Enums;
using ProtonVPN.Client.Core.Messages;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Auth;
using ProtonVPN.Client.Logic.Auth.Contracts;
using ProtonVPN.Client.Logic.Auth.Contracts.Enums;
using ProtonVPN.Client.Logic.Auth.Contracts.Messages;
using ProtonVPN.Client.Logic.Auth.Contracts.Models;
using ProtonVPN.Client.Logic.Connection.Contracts.GuestHole;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.UI.Login.Bases;
using ProtonVPN.Client.UI.Login.Enums;
using ProtonVPN.Client.UI.Login.Overlays;
using ProtonVPN.Common.Core.Extensions;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.Logging.Contracts.Events.AppLogs;
using ProtonVPN.Logging.Contracts.Events.UserLogs;

namespace ProtonVPN.Client.UI.Login.Pages;

public partial class SignInPageViewModel : LoginPageViewModelBase,
    IEventMessageReceiver<LoggedOutMessage>
{
    private readonly IUrlsBrowser _urlsBrowser;
    private readonly IUserAuthenticator _userAuthenticator;
    private readonly IEventMessageSender _eventMessageSender;
    private readonly IApiAvailabilityVerifier _apiAvailabilityVerifier;
    private readonly IGuestHoleManager _guestHoleManager;
    private readonly ISessionSettings _sessionSettings;
    private readonly ISettings _settings;
    private readonly ICentralCredentialClient _centralCredentialClient;
    private readonly IUnauthSessionManager _unauthSessionManager;
    private readonly SsoLoginOverlayViewModel _ssoLoginOverlayViewModel;
    private readonly IMainWindowViewNavigator _mainWindowViewNavigator;

    private string? _storedActualUsername;
    private string? _storedActualPassword;
    private string _maskedStoredUsername = string.Empty;
    private bool _isApplyingStoredMask;
    private bool _hasAttemptedStartupAutoSignIn;
    private bool _suppressAutoSignInAfterLogout;

    public event EventHandler? OnPasswordClearRequested;
    public event EventHandler<string>? OnPasswordSentinelRequested;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand))]
    [NotifyPropertyChangedFor(nameof(IsSignInFormEnabled))]
    private bool _isSigningIn;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand))]
    [NotifyPropertyChangedFor(nameof(UsernameFieldLabel))]
    [NotifyPropertyChangedFor(nameof(SwitchPageLabel))]
    [NotifyPropertyChangedFor(nameof(IsSrpFormType))]
    [NotifyPropertyChangedFor(nameof(IsSsoFormType))]
    [NotifyPropertyChangedFor(nameof(IsSwitchFormButtonVisible))]
    private SignInFormType _signInFormType;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand))]
    private string _username = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand))]
    private SecureString _password = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CreateAccountCommand))]
    private bool _isToShowCreateAccountSpinner;

    [ObservableProperty]
    private bool _isToShowUsernameError;

    [ObservableProperty]
    private bool _isToShowPasswordError;

    [ObservableProperty]
    private bool _isRememberCredentialsEnabled = true;

    [ObservableProperty]
    private bool _isAutoSignInWithStoredCredentialsEnabled = true;

    [ObservableProperty]
    private bool _isUsingStoredUsername;

    [ObservableProperty]
    private bool _isUsingStoredPassword;

    [ObservableProperty]
    private bool _hasSavedCredentials;

    [ObservableProperty]
    private bool _isCentralServerPanelExpanded;

    [ObservableProperty]
    private string _centralServerUrl = DefaultSettings.CentralCredentialServerUrl;

    [ObservableProperty]
    private string _centralSessionToken = string.Empty;

    [ObservableProperty]
    private string _centralEnrollmentCode = string.Empty;

    [ObservableProperty]
    private string _centralTargetCredentialId = string.Empty;

    [ObservableProperty]
    private string _centralStatusMessage = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RequestCentralTokenCommand))]
    [NotifyCanExecuteChangedFor(nameof(FetchCentralCredentialCommand))]
    private bool _isFetchingCentralCredential;

    private AuthError _authError;

    public bool HasCentralStatusMessage => !string.IsNullOrWhiteSpace(CentralStatusMessage);

    public bool IsSignInFormEnabled => !IsSigningIn;

    public bool IsSrpFormType => SignInFormType == SignInFormType.SRP;

    public bool IsSsoFormType => SignInFormType == SignInFormType.SSO;

    public bool IsSwitchFormButtonVisible => SignInFormType == SignInFormType.SRP;

    public string UsernameFieldLabel => SignInFormType switch
    {
        SignInFormType.SRP => Localizer.Get("SignIn_Form_Username"),
        SignInFormType.SSO => Localizer.Get("SignIn_Form_Email"),
        _ => Localizer.Get("SignIn_Form_Username")
    };

    public string SwitchPageLabel => SignInFormType switch
    {
        SignInFormType.SRP => Localizer.Get("SignIn_Form_SignInWithSso"),
        _ => string.Empty
    };

    public string CreateAccountUrl => _urlsBrowser.CreateAccount;

    public AuthError AuthError => _authError;

    private bool CanCreateAccount => !IsToShowCreateAccountSpinner;

    public SignInPageViewModel(
        ILoginViewNavigator parentViewNavigator,
        IUrlsBrowser urlsBrowser,
        IUserAuthenticator userAuthenticator,
        IEventMessageSender eventMessageSender,
        IApiAvailabilityVerifier apiAvailabilityVerifier,
        IGuestHoleManager guestHoleManager,
        ISessionSettings sessionSettings,
        ISettings settings,
        ICentralCredentialClient centralCredentialClient,
        IUnauthSessionManager unauthSessionManager,
        SsoLoginOverlayViewModel ssoLoginOverlayViewModel,
        IViewModelHelper viewModelHelper,
        IMainWindowViewNavigator mainWindowViewNavigator)
        : base(parentViewNavigator, viewModelHelper)
    {
        _urlsBrowser = urlsBrowser;
        _userAuthenticator = userAuthenticator;
        _eventMessageSender = eventMessageSender;
        _apiAvailabilityVerifier = apiAvailabilityVerifier;
        _guestHoleManager = guestHoleManager;
        _sessionSettings = sessionSettings;
        _settings = settings;
        _centralCredentialClient = centralCredentialClient;
        _unauthSessionManager = unauthSessionManager;
        _ssoLoginOverlayViewModel = ssoLoginOverlayViewModel;
        _mainWindowViewNavigator = mainWindowViewNavigator;
    }

    [RelayCommand(CanExecute = nameof(CanSignIn))]
    public async Task SignInAsync()
    {
        if (!ValidateForm())
        {
            return;
        }

        try
        {
            IsSigningIn = true;

            _eventMessageSender.Send(new LoginStateChangedMessage(LoginState.Authenticating));

            AuthResult result = SignInFormType switch
            {
                SignInFormType.SRP => await HandleSrpLoginAsync(),
                SignInFormType.SSO => await HandleSsoLoginAsync(),
                _ => throw new NotSupportedException($"{SignInFormType} login is not supported.")
            };

            if (result.Success)
            {
                HandleSuccess();
            }
            else
            {
                HandleError(result);
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Info<UserLog>("Authentication was cancelled by the user.");
        }
        catch (Exception e)
        {
            Logger.Error<UserLog>("An error occurred during authentication.", e);
            _eventMessageSender.Send(new LoginStateChangedMessage(LoginState.Error, AuthError.Unknown, e.Message));
        }
        finally
        {
            IsSigningIn = false;
        }
    }

    private bool ValidateForm()
    {
        switch (SignInFormType)
        {
            case SignInFormType.SRP:
                IsToShowUsernameError = string.IsNullOrWhiteSpace(GetEffectiveUsername());
                IsToShowPasswordError = !IsUsingStoredPassword && (Password is null || Password.Length == 0);
                break;
            case SignInFormType.SSO:
                string effectiveUser = GetEffectiveUsername();
                IsToShowUsernameError = string.IsNullOrWhiteSpace(effectiveUser) || !effectiveUser.IsValidEmailAddress();
                break;
        }

        return !IsToShowUsernameError && !IsToShowPasswordError;
    }

    private bool CanSignIn()
    {
        return !IsSigningIn;
    }

    private async Task<AuthResult> HandleSrpLoginAsync()
    {
        string effectiveUsername = GetEffectiveUsername();
        SecureString effectivePassword = IsUsingStoredPassword && !string.IsNullOrEmpty(_storedActualPassword)
            ? _storedActualPassword.ToSecureString()
            : Password;

        try
        {
            AuthResult result = await _userAuthenticator.LoginUserAsync(effectiveUsername, effectivePassword);
            if (result.Success)
            {
                PersistCredentialsAfterSuccess(effectiveUsername, effectivePassword.ToUnsecureString());
            }

            return result;
        }
        finally
        {
            if (!IsRememberCredentialsEnabled)
            {
                Password = new();
                OnPasswordClearRequested?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    private async Task<AuthResult> HandleSsoLoginAsync()
    {
        SsoAuthResult result = await _userAuthenticator.StartSsoAuthAsync(GetEffectiveUsername());

        return result.Success
            ? await _ssoLoginOverlayViewModel.AuthenticateAsync(result.SsoChallengeToken)
            : result;
    }

    private void HandleSuccess()
    {
        _authError = AuthError.None;
        _eventMessageSender.Send(new LoginStateChangedMessage(LoginState.Success));
    }

    private void HandleError(AuthResult result)
    {
        _authError = result.Value;

        switch (result.Value)
        {
            case AuthError.TwoFactorRequired:
                _eventMessageSender.Send(new LoginStateChangedMessage(LoginState.TwoFactorRequired));
                break;

            case AuthError.NoVpnAccess:
                _mainWindowViewNavigator.NavigateToNoServersViewAsync();
                break;

            case AuthError.SwitchToSSO:
            case AuthError.SwitchToSRP:
                SwitchLoginForm();
                goto default;

            default:
                _eventMessageSender.Send(new LoginStateChangedMessage(LoginState.Error, result.Value, result.Error));
                break;
        }
    }

    [RelayCommand]
    public void SwitchLoginForm()
    {
        SignInFormType = SignInFormType switch
        {
            SignInFormType.SRP => SignInFormType.SSO,
            SignInFormType.SSO => SignInFormType.SRP,
            _ => SignInFormType.SRP,
        };
    }

    [RelayCommand(CanExecute = nameof(CanCreateAccount))]
    public async Task CreateAccountAsync()
    {
        try
        {
            IsToShowCreateAccountSpinner = true;

            Result? result;

            bool isSignUpPageAccessible = await _apiAvailabilityVerifier.IsSignUpPageAccessibleAsync();
            if (isSignUpPageAccessible)
            {
                Logger.Info<AppLog>("Opening create account page.");
                result = await OpenCreateAccountPageAsync();
            }
            else
            {
                Logger.Info<AppLog>("API is not accessible, opening create account page through guest hole.");
                result = await _guestHoleManager.ExecuteAsync<Result>(OpenCreateAccountPageAsync);
            }

            if (result?.Success == true)
            {
                Logger.Info<AppLog>("Create account page opened successfully.");
            }
            else
            {
                Logger.Error<AppLog>($"Failed to open create account page. Error: {result?.Error ?? "null"}");
            }
        }
        catch (Exception e)
        {
            Logger.Error<AppLog>("Failed to open create account page.", e);
        }
        finally
        {
            IsToShowCreateAccountSpinner = false;
        }
    }

    private async Task<Result> OpenCreateAccountPageAsync()
    {
        try
        {
            _urlsBrowser.BrowseTo(_urlsBrowser.CreateAccount);
            // Delay for page to load
            await Task.Delay(3000); 
            return Result.Ok();
        }
        catch (Exception e)
        {
            return Result.Fail(e.Message);
        }
    }

    public void Receive(LoggedOutMessage message)
    {
        _suppressAutoSignInAfterLogout = true;
    }

    public void OnUserEditedPassword(SecureString newPassword)
    {
        if (_isApplyingStoredMask)
        {
            return;
        }

        IsUsingStoredPassword = false;
        _storedActualPassword = null;
        Password = newPassword;
    }

    [RelayCommand]
    private void ToggleCentralServerPanel()
    {
        IsCentralServerPanelExpanded = !IsCentralServerPanelExpanded;
    }

    [RelayCommand]
    private void ClearSavedCredentials()
    {
        _settings.RememberedUsername = null;
        _settings.RememberedPassword = null;
        _settings.CentralCredentialSessionToken = null;
        _isApplyingStoredMask = true;
        try
        {
            _storedActualUsername = null;
            _storedActualPassword = null;
            _maskedStoredUsername = string.Empty;
            IsUsingStoredUsername = false;
            IsUsingStoredPassword = false;
            HasSavedCredentials = false;
            Username = string.Empty;
            Password = new();
            CentralSessionToken = string.Empty;
            CentralStatusMessage = string.Empty;
            OnPasswordClearRequested?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            _isApplyingStoredMask = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanFetchCentralCredential))]
    private async Task RequestCentralTokenAsync()
    {
        try
        {
            IsFetchingCentralCredential = true;
            CentralStatusMessage = string.Empty;

            CentralTokenIssueResult res = await _centralCredentialClient.RequestSessionTokenAsync(
                CentralServerUrl,
                CentralEnrollmentCode,
                CentralTargetCredentialId);

            if (!res.Success || string.IsNullOrWhiteSpace(res.SessionToken))
            {
                CentralStatusMessage = res.Error ?? "Failed to request session token.";
                return;
            }

            CentralSessionToken = res.SessionToken;
            _settings.CentralCredentialServerUrl = CentralServerUrl.Trim();
            _settings.CentralCredentialSessionToken = res.SessionToken;
            CentralStatusMessage = $"Token ready for {res.MaskedUsername} (expires {res.ExpiresAtUtc:HH:mm dd MMM} UTC)";
        }
        finally
        {
            IsFetchingCentralCredential = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanFetchCentralCredential))]
    private async Task FetchCentralCredentialAsync()
    {
        try
        {
            IsFetchingCentralCredential = true;
            CentralStatusMessage = string.Empty;

            if (string.IsNullOrWhiteSpace(CentralSessionToken) && !string.IsNullOrWhiteSpace(CentralEnrollmentCode))
            {
                CentralTokenIssueResult issued = await _centralCredentialClient.RequestSessionTokenAsync(
                    CentralServerUrl,
                    CentralEnrollmentCode,
                    CentralTargetCredentialId);

                if (!issued.Success || string.IsNullOrWhiteSpace(issued.SessionToken))
                {
                    CentralStatusMessage = issued.Error ?? "Failed to request session token.";
                    return;
                }

                CentralSessionToken = issued.SessionToken;
            }

            CentralCredentialFetchResult fetched = await _centralCredentialClient.FetchCredentialAsync(
                CentralServerUrl,
                CentralSessionToken);

            if (!fetched.Success || string.IsNullOrWhiteSpace(fetched.Username) || string.IsNullOrEmpty(fetched.Password))
            {
                CentralStatusMessage = fetched.Error ?? "Failed to fetch credential from central server.";
                return;
            }

            _settings.CentralCredentialServerUrl = CentralServerUrl.Trim();
            _settings.CentralCredentialSessionToken = CentralSessionToken.Trim();
            IsRememberCredentialsEnabled = true;
            PersistCredentialsAfterSuccess(fetched.Username, fetched.Password);
            LoadStoredMaskedCredentials();
            CentralStatusMessage = $"Loaded encrypted credential ({fetched.MaskedUsername}). Signing in...";

            if (SignInCommand.CanExecute(null))
            {
                await SignInAsync();
            }
        }
        finally
        {
            IsFetchingCentralCredential = false;
        }
    }

    private bool CanFetchCentralCredential() => !IsFetchingCentralCredential;

    protected override void OnActivated()
    {
        base.OnActivated();

        _unauthSessionManager.Revoke();

        IsRememberCredentialsEnabled = _settings.IsRememberCredentialsEnabled;
        IsAutoSignInWithStoredCredentialsEnabled = _settings.IsAutoSignInWithStoredCredentialsEnabled;
        if (!string.IsNullOrWhiteSpace(_settings.CentralCredentialServerUrl))
        {
            CentralServerUrl = _settings.CentralCredentialServerUrl!;
        }
        if (!string.IsNullOrWhiteSpace(_settings.CentralCredentialSessionToken))
        {
            CentralSessionToken = _settings.CentralCredentialSessionToken!;
        }

        if (_userAuthenticator.IsAutoLogin != true && SignInCommand.CanExecute(null))
        {
            if (!string.IsNullOrEmpty(_sessionSettings.Username))
            {
                Username = _sessionSettings.Username.Trim();

                if (!string.IsNullOrEmpty(_sessionSettings.Password))
                {
                    Password = _sessionSettings.Password.Trim().ToSecureString();

                    SignInCommand.Execute(null);
                    return;
                }
            }

            LoadStoredMaskedCredentials();

            bool shouldAutoSignInOnLaunch = !_suppressAutoSignInAfterLogout
                && !_hasAttemptedStartupAutoSignIn
                && IsAutoSignInWithStoredCredentialsEnabled
                && IsRememberCredentialsEnabled
                && IsUsingStoredUsername
                && IsUsingStoredPassword;

            _hasAttemptedStartupAutoSignIn = true;
            _suppressAutoSignInAfterLogout = false;

            if (shouldAutoSignInOnLaunch)
            {
                SignInCommand.Execute(null);
            }
        }
    }

    partial void OnUsernameChanged(string value)
    {
        if (_isApplyingStoredMask)
        {
            return;
        }

        if (IsUsingStoredUsername && !string.Equals(value, _maskedStoredUsername, StringComparison.Ordinal))
        {
            IsUsingStoredUsername = false;
            _storedActualUsername = null;
            _maskedStoredUsername = string.Empty;

            if (IsUsingStoredPassword)
            {
                _isApplyingStoredMask = true;
                try
                {
                    IsUsingStoredPassword = false;
                    _storedActualPassword = null;
                    Password = new();
                    OnPasswordClearRequested?.Invoke(this, EventArgs.Empty);
                }
                finally
                {
                    _isApplyingStoredMask = false;
                }
            }
        }
    }

    partial void OnIsRememberCredentialsEnabledChanged(bool value)
    {
        _settings.IsRememberCredentialsEnabled = value;
        if (!value)
        {
            IsAutoSignInWithStoredCredentialsEnabled = false;
        }
    }

    partial void OnIsAutoSignInWithStoredCredentialsEnabledChanged(bool value)
    {
        _settings.IsAutoSignInWithStoredCredentialsEnabled = value;
    }

    partial void OnCentralStatusMessageChanged(string value)
    {
        OnPropertyChanged(nameof(HasCentralStatusMessage));
    }

    private string GetEffectiveUsername()
    {
        return IsUsingStoredUsername && !string.IsNullOrWhiteSpace(_storedActualUsername)
            ? _storedActualUsername.Trim()
            : Username?.Trim() ?? string.Empty;
    }

    private void PersistCredentialsAfterSuccess(string actualUsername, string actualPassword)
    {
        _settings.IsRememberCredentialsEnabled = IsRememberCredentialsEnabled;
        _settings.IsAutoSignInWithStoredCredentialsEnabled = IsAutoSignInWithStoredCredentialsEnabled;

        if (IsRememberCredentialsEnabled && !string.IsNullOrWhiteSpace(actualUsername) && !string.IsNullOrEmpty(actualPassword))
        {
            _settings.RememberedUsername = actualUsername.Trim();
            _settings.RememberedPassword = actualPassword;
            LoadStoredMaskedCredentials();
        }
        else if (!IsRememberCredentialsEnabled)
        {
            _settings.RememberedUsername = null;
            _settings.RememberedPassword = null;
            HasSavedCredentials = false;
        }
    }

    private void LoadStoredMaskedCredentials()
    {
        string? savedUser = _settings.RememberedUsername;
        string? savedPass = _settings.RememberedPassword;

        _isApplyingStoredMask = true;
        try
        {
            if (IsRememberCredentialsEnabled && !string.IsNullOrWhiteSpace(savedUser))
            {
                _storedActualUsername = savedUser.Trim();
                _maskedStoredUsername = CredentialMasking.MaskAccount(_storedActualUsername);
                IsUsingStoredUsername = true;
                Username = _maskedStoredUsername;
            }
            else
            {
                _storedActualUsername = null;
                _maskedStoredUsername = string.Empty;
                IsUsingStoredUsername = false;
                Username = string.Empty;
            }

            if (IsRememberCredentialsEnabled && !string.IsNullOrEmpty(savedPass) && IsUsingStoredUsername)
            {
                _storedActualPassword = savedPass;
                IsUsingStoredPassword = true;
                Password = new();
                OnPasswordSentinelRequested?.Invoke(this, CredentialMasking.MaskedPasswordSentinel);
            }
            else
            {
                _storedActualPassword = null;
                IsUsingStoredPassword = false;
                Password = new();
                OnPasswordClearRequested?.Invoke(this, EventArgs.Empty);
            }

            HasSavedCredentials = IsUsingStoredUsername || IsUsingStoredPassword;
        }
        finally
        {
            _isApplyingStoredMask = false;
        }
    }

    partial void OnSignInFormTypeChanged(SignInFormType oldValue, SignInFormType newValue)
    {
        IsToShowUsernameError = false;
        IsToShowPasswordError = false;
    }
}