import React, { useRef, useState } from 'react';
import { startOidcLogin } from '../services/oidcAuth';
import { showToast } from './Toast';
import { isWeb } from '../services/platform';

interface OidcLoginButtonProps {
  displayName?: string;
  disabled?: boolean;
  returnTo?: string;
}

const OidcLoginButton: React.FC<OidcLoginButtonProps> = ({
  displayName = 'Single sign-on',
  disabled = false,
  returnTo,
}) => {
  const started = useRef(false);
  const [redirecting, setRedirecting] = useState(false);
  if (!isWeb()) return null;
  const label = displayName.trim() || 'Single sign-on';

  const handleClick = () => {
    if (started.current) return;
    started.current = true;
    setRedirecting(true);
    try {
      startOidcLogin(returnTo);
    } catch (err) {
      started.current = false;
      setRedirecting(false);
      showToast(err instanceof Error ? err.message : 'Could not start single sign-on', 'error');
    }
  };

  return (
    <button
      type="button"
      className="dialog-btn settings-sso-btn"
      onClick={handleClick}
      disabled={disabled || redirecting}
    >
      {redirecting ? 'Redirecting…' : `Continue with ${label}`}
    </button>
  );
};

export default OidcLoginButton;
