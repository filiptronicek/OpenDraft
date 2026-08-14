import React from 'react';
import { useAuthenticatedAssetUrl } from '../hooks/useAuthenticatedAssetUrl';

interface AuthenticatedAssetImageProps
  extends Omit<React.ImgHTMLAttributes<HTMLImageElement>, 'src'> {
  src: string | null | undefined;
}

/** An img whose protected HTTP source is delivered through an authenticated blob lease. */
export const AuthenticatedAssetImage = React.forwardRef<
  HTMLImageElement,
  AuthenticatedAssetImageProps
>(({ src, ...props }, ref) => {
  const { url } = useAuthenticatedAssetUrl(src);
  return <img {...props} ref={ref} src={url || undefined} />;
});

AuthenticatedAssetImage.displayName = 'AuthenticatedAssetImage';
