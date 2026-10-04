/* Wyjatek w renderze (np. nietypowe `data` w starym powiadomieniu) bez tej
   bariery odmontowywal cale drzewo React - bialy ekran calego panelu.
   Z bariera pada tylko jej fragment, reszta panelu dziala dalej. */
import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('kidwatch: blad renderu', error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    if (this.props.fallback !== undefined) return this.props.fallback;
    return (
      <div className="empty">
        <span className="badge bad">Ten widok się wysypał</span>{' '}
        <button type="button" className="btn-ghost" onClick={() => this.setState({ error: null })}>
          Spróbuj ponownie
        </button>
      </div>
    );
  }
}
