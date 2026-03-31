import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "./ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.href = "/";
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen p-6 bg-slate-950 text-slate-50">
          <div className="w-full max-w-md p-8 rounded-xl border border-slate-800 bg-slate-900 shadow-2xl text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-900/20 text-red-500 mb-6">
              <AlertTriangle size={32} />
            </div>
            <h1 className="text-2xl font-bold mb-2">Unexpected Application Error</h1>
            <p className="text-slate-400 mb-8">
              Something went wrong while rendering this page. We've logged the error and you can try refreshing.
            </p>
            {this.state.error && (
              <div className="mb-8 p-4 rounded-lg bg-slate-950 border border-slate-800 text-left overflow-hidden">
                <p className="text-xs font-mono text-red-400 break-words">
                  {this.state.error.toString()}
                </p>
              </div>
            )}
            <div className="flex flex-col gap-3">
              <Button 
                onClick={() => window.location.reload()}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Reload Page
              </Button>
              <Button 
                variant="outline"
                onClick={this.handleReset}
                className="w-full border-slate-700 hover:bg-slate-800 text-slate-300"
              >
                Go to Dashboard
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.children;
  }
}
