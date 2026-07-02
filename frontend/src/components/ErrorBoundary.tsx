import { Component, ErrorInfo, ReactNode } from "react";

// A render-time safety net for a single panel. Findings and nodes carry agent-authored,
// untrusted evidence, so a malformed field can throw mid-render; without a boundary that
// throw propagates to the router and white-screens the ENTIRE workspace (the observed
// "Unexpected Application Error"). This confines the failure to the one panel, keeping the
// list, graph, and every other finding usable. Give it a `key` that changes with the
// selected entity so selecting a different (well-formed) item remounts it clean.
export default class ErrorBoundary extends Component<
  { children: ReactNode; label?: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface it for debugging without taking down the app.
    console.error("Panel render error", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="empty" style={{ padding: 16 }}>
          <p>Couldn't render {this.props.label || "this item"} — its data appears malformed.</p>
          <p className="muted" style={{ fontSize: 11, whiteSpace: "pre-wrap" }}>
            {String(this.state.error.message || this.state.error)}
          </p>
        </div>
      );
    }
    return <>{this.props.children}</>;
  }
}
