import { useNavigate } from 'react-router';
import { Shield, BookOpen, Clock, Lock, Target, Server, Activity } from 'lucide-react';

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen text-slate-900 aurora-bg selection:bg-emerald-400/30">
      <header className="glass-surface border-b border-slate-200/70 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-emerald-300/90 via-teal-400 to-sky-500 flex items-center justify-center shadow-lg glow-ring">
              <Shield className="w-6 h-6 text-slate-950" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 font-display tracking-tight">SecureScope</h1>
              <p className="text-[10px] uppercase tracking-[0.3em] text-slate-600 font-semibold">
                Advanced Reconnaissance Engine
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/signin')}
              className="text-sm font-semibold px-4 py-2 rounded-xl bg-emerald-400 text-slate-950 shadow-lg shadow-emerald-200/40 hover:bg-emerald-500 transition-all"
            >
              Operator Login
            </button>
            <button
              onClick={() => navigate('/admin/users/new')}
              className="text-sm font-semibold px-4 py-2 rounded-xl bg-emerald-400 text-slate-950 shadow-lg shadow-emerald-200/40 hover:bg-emerald-500 transition-all"
            >
              Create User
            </button>
          </div>
        </div>
      </header>

      <main>
        <section className="relative overflow-hidden border-b border-slate-200/70">
          <div className="absolute inset-0 grid-overlay"></div>
          <div className="absolute -top-24 right-12 w-72 h-72 rounded-full bg-emerald-400/20 blur-3xl animate-float"></div>
          <div className="absolute bottom-0 left-10 w-64 h-64 rounded-full bg-amber-300/10 blur-3xl animate-float"></div>

          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-28 relative z-10 text-center">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-100 border border-emerald-200 text-emerald-700 text-xs font-bold uppercase tracking-wider mb-8 animate-pulse-glow">
              <span className="w-2 h-2 rounded-full bg-emerald-300"></span>
              Live Architecture Active
            </div>

            <div className="stagger-fade">
              <h2 className="text-5xl md:text-6xl font-extrabold text-slate-900 tracking-tight text-glow font-display">
                Institutional Attack Surface Intelligence
              </h2>
              <p className="text-xl text-slate-700 max-w-3xl mx-auto mt-6 leading-relaxed">
                SecureScope is a high-performance reconnaissance and vulnerability scanner deployed to identify external
                attack surfaces within 60 seconds. Powered by enterprise-grade tooling and governed by Zero Trust pipelines.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center mt-10">
                <a
                  href="#guide"
                  className="inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-xl bg-emerald-400 text-slate-950 font-bold text-lg hover:bg-emerald-500 transition-all hover:-translate-y-0.5"
                >
                  <BookOpen className="w-5 h-5 text-slate-950" />
                  Read the Guide
                </a>
              </div>
            </div>
          </div>
        </section>

        <section id="guide" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 scroll-mt-20">
          <div className="text-center mb-16">
            <h3 className="text-3xl font-bold text-slate-900 font-display">Official Platform Documentation</h3>
            <p className="text-slate-600 max-w-2xl mx-auto mt-4">
              Please review the system architecture rules and scanning protocols before executing any external operations
              through SecureScope.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 stagger-fade">
            <div className="glass-surface rounded-2xl p-8 border border-slate-200 hover:-translate-y-1 transition-all">
              <div className="w-12 h-12 rounded-lg bg-red-100 flex items-center justify-center mb-6">
                <Lock className="w-6 h-6 text-red-700" />
              </div>
              <h4 className="text-xl font-bold text-slate-900 mb-3 font-display">Zero Trust Onboarding</h4>
              <p className="text-slate-600 leading-relaxed text-sm">
                Creating an account simply establishes your identity. You will be locked out of tool execution until your
                identity clears an active Administrator review within the System Requests queue.
              </p>
            </div>

            <div className="glass-surface rounded-2xl p-8 border border-slate-200 hover:-translate-y-1 transition-all">
              <div className="w-12 h-12 rounded-lg bg-emerald-100 flex items-center justify-center mb-6">
                <Activity className="w-6 h-6 text-emerald-700" />
              </div>
              <h4 className="text-xl font-bold text-slate-900 mb-3 font-display">Normal Scans (Passive)</h4>
              <p className="text-slate-600 leading-relaxed text-sm">
                Available to all verified Operators. Normal scans use public intelligence (WHOIS, DNS records) to silently
                map target architectures without touching the target's actual infrastructure.
              </p>
            </div>

            <div className="glass-surface rounded-2xl p-8 border border-slate-200 hover:-translate-y-1 transition-all">
              <div className="w-12 h-12 rounded-lg bg-amber-100 flex items-center justify-center mb-6">
                <Target className="w-6 h-6 text-amber-700" />
              </div>
              <h4 className="text-xl font-bold text-slate-900 mb-3 font-display">Quick Scans (Active)</h4>
              <p className="text-slate-600 leading-relaxed text-sm">
                Strictly regulated and restricted to Administrator override. Quick Scans actively probe firewalls and engage
                ports natively. Use extreme caution on unauthorized assets.
              </p>
            </div>

            <div className="glass-surface rounded-2xl p-8 border border-slate-200 hover:-translate-y-1 transition-all">
              <div className="w-12 h-12 rounded-lg bg-sky-100 flex items-center justify-center mb-6">
                <Clock className="w-6 h-6 text-sky-700" />
              </div>
              <h4 className="text-xl font-bold text-slate-900 mb-3 font-display">60-Second Budgets</h4>
              <p className="text-slate-600 leading-relaxed text-sm">
                Our infrastructure mitigates DoS risks heavily. Complex target pipelines automatically crash and safely
                self-kill if analysis execution drags past the strict 60-second operational ceiling.
              </p>
            </div>

            <div className="glass-surface rounded-2xl p-8 border border-slate-200 hover:-translate-y-1 transition-all lg:col-span-2">
              <div className="w-12 h-12 rounded-lg bg-sky-100 flex items-center justify-center mb-6">
                <Server className="w-6 h-6 text-sky-700" />
              </div>
              <h4 className="text-xl font-bold text-slate-900 mb-3 font-display">Actionable Mitigation Telemetry</h4>
              <p className="text-slate-600 leading-relaxed text-sm">
                Scan reports deliver more than theoretical metrics. Dive directly into your individual scan vulnerabilities
                to expose exact Raw Data Source output lines dynamically tied to precise mitigation directives mapping how to
                fix the flaw immediately.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-200/70 py-12 bg-white/70">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-emerald-700" />
            <span className="text-lg font-bold text-slate-900 font-display">SecureScope</span>
          </div>
          <p className="text-slate-500 text-sm text-center">
            &copy; {new Date().getFullYear()} SecureScope Architecture. Educational and Authorized Assessment Protocols only.
            All system metrics tightly monitored.
          </p>
        </div>
      </footer>
    </div>
  );
}



