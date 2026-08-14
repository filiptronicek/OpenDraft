import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { collabAuthApi, handleAuthResponse } from '../services/collabAuth';
import { completeOidcCallback, oidcCallbackErrorMessage } from '../services/oidcAuth';

type CallbackStatus = 'pending' | 'success' | 'error';

const OidcCallbackRoute: React.FC = () => {
  const navigate = useNavigate();
  const [callbackLocation] = useState(() => ({
    search: window.location.search,
    pathname: window.location.pathname,
  }));
  const [status, setStatus] = useState<CallbackStatus>('pending');
  const [message, setMessage] = useState('');
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    (async () => {
      try {
        const { result, returnTo } = await completeOidcCallback({
          ...callbackLocation,
          exchange: collabAuthApi.exchangeOidcCode,
        });
        handleAuthResponse(result);
        setStatus('success');
        navigate(returnTo, { replace: true });
      } catch (err) {
        setStatus('error');
        setMessage(oidcCallbackErrorMessage(err));
      }
    })();
  }, [callbackLocation, navigate]);

  return (
    <div className="auth-callback-page">
      <div className="auth-callback-card" role={status === 'error' ? 'alert' : 'status'}>
        {status === 'pending' && (
          <>
            <h2>Finishing sign-in…</h2>
            <p>Please wait while OpenDraft verifies your one-time code.</p>
          </>
        )}
        {status === 'success' && (
          <>
            <h2>Signed in</h2>
            <p>Returning to OpenDraft…</p>
          </>
        )}
        {status === 'error' && (
          <>
            <h2>Sign-in failed</h2>
            <p>{message}</p>
            <button
              type="button"
              className="dialog-btn dialog-btn-primary"
              onClick={() => navigate('/', { replace: true })}
            >
              Return to OpenDraft
            </button>
          </>
        )}
      </div>
    </div>
  );
};

export default OidcCallbackRoute;
