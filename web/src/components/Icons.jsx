/* Ikony liniowe inline (SVG, bez biblioteki). Jedna grubosc kreski i jedna
   siatka 24x24 - zeby nawigacja, karty i przyciski mowily tym samym jezykiem.
   Kolor bierze sie z currentColor; ikona jest ozdobnikiem (aria-hidden),
   etykiete niesie zawsze tekst albo aria-label przycisku. */
import React from 'react';

const PATHS = {
  logo: (
    <>
      <rect x="3.5" y="7" width="17" height="13" rx="4" />
      <path d="M8.5 2.5 12 7l3.5-4.5" />
      <circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none" />
      <path d="M9.5 16.5c1.4 1 3.6 1 5 0" />
    </>
  ),
  pulpit: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.8" />
    </>
  ),
  bell: (
    <>
      <path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z" />
      <path d="M10 20.5a2.2 2.2 0 0 0 4 0" />
    </>
  ),
  screens: (
    <>
      <rect x="2.5" y="4" width="13" height="10" rx="1.8" />
      <path d="M6.5 18h5M9 14v4" />
      <rect x="17.5" y="7" width="4" height="11" rx="1.2" />
    </>
  ),
  usage: (
    <>
      <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
    </>
  ),
  trends: <path d="M3 17l6-6 4 4 8-8M15 7h6v6" />,
  day: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7v5l3.5 2" />
    </>
  ),
  mdm: (
    <>
      <path d="M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6z" />
      <path d="m9 12 2 2 4-4" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </>
  ),
  more: (
    <>
      <circle cx="5" cy="12" r="1.3" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1.3" fill="currentColor" stroke="none" />
    </>
  ),
  chevron: <path d="m6 9 6 6 6-6" />,
  tablet: (
    <>
      <rect x="5" y="2.5" width="14" height="19" rx="2.5" />
      <path d="M11 18.5h2" />
    </>
  ),
  tv: (
    <>
      <rect x="2.5" y="4" width="19" height="13" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </>
  ),
  pause: <path d="M9 5v14M15 5v14" />,
  play: <path d="M7 4.5v15l12-7.5z" />,
  gamepad: (
    <>
      <path d="M7 8h10a4.5 4.5 0 0 1 4.4 5.5l-.8 3.4a2.3 2.3 0 0 1-4 .9L14.5 16h-5l-2.1 1.8a2.3 2.3 0 0 1-4-.9l-.8-3.4A4.5 4.5 0 0 1 7 8z" />
      <path d="M8 11v3M6.5 12.5h3" />
      <circle cx="16" cy="12" r=".8" fill="currentColor" stroke="none" />
    </>
  ),
  home: <path d="M3.5 11 12 4l8.5 7M6 9.5V20h12V9.5" />,
};

export default function Icon({ name, size = 20, className = '', ...rest }) {
  return (
    <svg className={`icon ${className}`} width={size} height={size} viewBox="0 0 24 24"
         fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"
         strokeLinejoin="round" aria-hidden="true" focusable="false" {...rest}>
      {PATHS[name] || PATHS.more}
    </svg>
  );
}
