import { Component, type ReactNode } from 'react';

type Props = { label: string; children: ReactNode; resetKey?: unknown };
type State = { error: Error | null };

/** Contains a rendering failure to one region so the rest of the application stays usable. */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };
  static getDerivedStateFromError(error: Error): State { return { error }; }
  componentDidUpdate(previous: Props) {
    if (this.state.error && previous.resetKey !== this.props.resetKey) this.setState({ error: null });
  }
  render() {
    if (!this.state.error) return this.props.children;
    return <div className="error boundary" role="alert" data-testid="error-boundary">
      <strong>{this.props.label} could not be displayed.</strong> {this.state.error.message}
      <button onClick={() => this.setState({ error: null })}>Retry</button>
    </div>;
  }
}
