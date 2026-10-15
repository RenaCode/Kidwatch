import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import Zaproszenie from './components/Zaproszenie.jsx';
import { isInvitePath } from './utils/zaproszenia.js';
import './index.css';

// /zaproszenie#<token>: ekran przyjecia zaproszenia - bez sesji panelu, bo
// zaproszony moze jeszcze nie miec konta (src/kidwatch/zaproszenia.py).
const Root = isInvitePath(window.location.pathname) ? Zaproszenie : App;

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
