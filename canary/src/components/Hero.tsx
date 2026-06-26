const TICKER_TEXT =
  '[ THREAT DETECTED: ASI-03 Prompt Injection ] · [ CAMPAIGN RX-041823 ACTIVE ] · [ AGENT: LLM-TOOL-BRIDGE COMPROMISED ] · [ DEFENDER: GUARDRAIL DEPLOYED ] · [ FINDING: SEVERITY CRITICAL ] · [ REPLAY VERIFICATION IN PROGRESS ] · '

interface HeroProps {
  onRunAudit?: () => void
}

export default function Hero({ onRunAudit }: HeroProps) {
  const stats = [
    { value: 'ASI10', label: 'Coverage', cls: 'animate-hero-stat-1', red: true },
    { value: 'ATLAS', label: 'Framework', cls: 'animate-hero-stat-2', red: false },
    { value: 'x500°', label: 'Attack Depth', cls: 'animate-hero-stat-3', red: false },
  ]

  return (
    <section className="relative w-full h-screen overflow-hidden bg-black">
      {/* Layer 1: Background video */}
      <video
        autoPlay
        muted
        loop
        playsInline
        className="absolute inset-0 w-full h-full object-cover animate-hero-video"
      >
        <source src="/hero.mp4" type="video/mp4" />
      </video>

      {/* Layer 2a: Full-frame darkening overlay */}
      <div className="absolute inset-0 bg-black/55 pointer-events-none z-[5]" />

      {/* Layer 2b: Bottom fade to solid black */}
      <div className="absolute inset-x-0 bottom-0 h-[65%] bg-gradient-to-t from-black via-black/60 to-transparent pointer-events-none z-[5]" />

      {/* Layer 3: Content */}
      <div className="relative z-10 h-full flex flex-col justify-end px-6 sm:px-10 md:px-16 lg:px-20 pb-12 md:pb-16 lg:pb-20">

        {/* Label */}
        <p className="animate-hero-label text-white/50 text-[10px] sm:text-xs tracking-[0.3em] uppercase font-light mb-6 md:mb-8">
          Autonomous Red-Team Engine. By Agent Canary.
        </p>

        {/* Threat ticker */}
        <div className="overflow-hidden mb-6 md:mb-8">
          <div className="animate-ticker whitespace-nowrap text-red-600/70 text-[10px] tracking-[0.15em] uppercase font-light">
            {(TICKER_TEXT).repeat(3)}
          </div>
        </div>

        {/* Two-column layout */}
        <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-10 lg:gap-20">

          {/* Left column */}
          <div className="flex-shrink-0">
            <h1
              className="animate-hero-title text-white font-bold uppercase leading-[0.9] tracking-[-0.06em]"
              style={{ fontSize: 'clamp(2.5rem, 8vw, 5rem)' }}
            >
              Adversarial<br />
              Agent<br />
              Evaluation
            </h1>

            {/* Meta line */}
            <div className="animate-hero-meta mt-6 flex items-center gap-6 text-white/40 text-[10px] sm:text-xs tracking-wider uppercase font-light">
              <span>Campaign: RX-041823</span>
              <span className="animate-hero-divider w-8 h-[1px] bg-red-600/40 inline-block" />
              <span>Mode: Sigma</span>
            </div>
          </div>

          {/* Right column */}
          <div className="flex flex-col gap-8 lg:max-w-md">
            <p className="animate-hero-description text-white/60 text-xs sm:text-sm leading-relaxed font-light">
              Autonomously discovering, evaluating, and remediating vulnerabilities across AI agent surfaces. Multi-agent orchestration exposes the most critical attack paths in enterprise agentic infrastructure.
            </p>

            {/* Stats */}
            <div className="flex items-end gap-8 sm:gap-12">
              {stats.map(({ value, label, cls, red }) => (
                <div key={label} className={`${cls} flex flex-col gap-1`}>
                  <span className={`${red ? 'text-red-500' : 'text-white'} text-2xl sm:text-3xl font-bold tracking-tight`}>
                    {value}
                  </span>
                  <span className="text-white/40 text-[10px] sm:text-xs uppercase tracking-wider font-light">
                    {label}
                  </span>
                </div>
              ))}
            </div>

            {/* CTA row */}
            <div className="animate-hero-cta flex gap-4">
              <button
                onClick={onRunAudit}
                className="px-6 py-3 bg-red-600 text-white text-xs uppercase tracking-[0.15em] font-medium hover:bg-red-500 transition-all duration-200"
              >
                Run Audit
              </button>
              <button className="px-6 py-3 border border-white/30 text-white text-xs uppercase tracking-[0.15em] font-light hover:border-white/60 transition-all duration-200">
                Request Access
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
