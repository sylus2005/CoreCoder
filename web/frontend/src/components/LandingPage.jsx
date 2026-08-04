import React, { useState, useRef, useEffect, useCallback } from 'react';
import '../landing.css';

// 字符集
const CHARS = 'ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');

// 颜色：头部亮紫 → 逐步变暗紫
const PALETTE = [
  '#c4b5fd',
  '#a78bfa',
  '#8b5cf6',
  '#7c3aed',
  '#6366f1',
  '#4f46e5',
  '#3730a3',
  '#312e81',
];

// ============================================================================
// Agent 数据
// ============================================================================
const AGENTS = [
  {
    icon: '🧠',
    name: 'c_review',
    title: 'C/C++ Memory Safety',
    description: 'Deep analysis of C/C++ source code for memory corruption vulnerabilities.',
    capabilities: [
      'Buffer Overflow (CWE-120)',
      'Use-After-Free (CWE-416)',
      'Integer Overflow (CWE-190)',
      'Format String (CWE-134)',
      'Null Pointer Dereference',
      'Hardcoded Secrets',
    ],
    gradient: 'linear-gradient(135deg, #6366f1, #4f46e5)',
  },
  {
    icon: '🔑',
    name: 'insecure_defaults',
    title: 'Configuration & Secrets',
    description: 'Scans for insecure defaults, hardcoded credentials, and misconfigurations.',
    capabilities: [
      'Hardcoded Credentials (CWE-798)',
      'Debug Mode Enabled (CWE-215)',
      'Insecure CORS (CWE-942)',
      'Weak File Permissions',
      'Default Passwords',
      'Dangerous Protocols',
    ],
    gradient: 'linear-gradient(135deg, #7c3aed, #6366f1)',
  },
  {
    icon: '💉',
    name: 'injection_scanner',
    title: 'Injection Detection',
    description: 'Pattern-based injection vulnerability scanner enhanced by LLM context analysis.',
    capabilities: [
      'SQL Injection (CWE-89)',
      'Command Injection (CWE-78)',
      'XSS / Cross-Site Scripting (CWE-79)',
      'Path Traversal (CWE-22)',
      'SSRF (CWE-918)',
      'Multi-language Support',
    ],
    gradient: 'linear-gradient(135deg, #8b5cf6, #7c3aed)',
  },
];

// ============================================================================
// Section 组件（内联）
// ============================================================================

function HeroSection({ children }) {
  return (
    <section className="landing-section hero-section">
      <div className="landing-hero">
        <div className="landing-badge">
          <span className="landing-badge-icon">&#x1F512;</span>
          INTELLIGENT CODE VULNERABILITY SCANNER
        </div>
        <h1 className="glitch-title" data-text="CoreCoder">
          CoreCoder
        </h1>
        <p className="typewriter-subtitle">
          Security Agent &#183; AI-Powered Code Audit
        </p>
        {children}
      </div>
    </section>
  );
}

function AgentsSection() {
  return (
    <section className="landing-section agents-section section-reveal">
      <div className="section-inner">
        <h2 className="section-title">
          Three Intelligent Security <span className="text-gradient">Agents</span>
        </h2>
        <p className="section-subtitle">
          Multi-dimensional code auditing with specialized AI-powered detection engines
        </p>
        <div className="agent-cards">
          {AGENTS.map((agent) => (
            <div className="agent-card" key={agent.name}>
              <div className="agent-card-header">
                <div className="agent-icon" style={{ background: agent.gradient }}>
                  {agent.icon}
                </div>
                <div>
                  <code className="agent-name">{agent.name}</code>
                  <h3>{agent.title}</h3>
                </div>
              </div>
              <p className="agent-desc">{agent.description}</p>
              <ul className="agent-caps">
                {agent.capabilities.map((cap) => (
                  <li key={cap}>{cap}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ToolsSection() {
  return (
    <section className="landing-section tools-section section-reveal">
      <div className="section-inner">
        <h2 className="section-title">
          AI-Powered <span className="text-gradient">Audit Pipeline</span>
        </h2>
        <p className="section-subtitle">
          From one-click scanning to AI-driven deep analysis — a complete security workflow
        </p>
        <div className="tools-grid">
          <div className="pipeline-visual">
            <div className="pipeline-step">
              <div className="step-icon">&#x26A1;</div>
              <div className="step-label">Start Audit</div>
              <div className="step-desc">One-click regex scan<br />across all files</div>
            </div>
            <div className="pipeline-arrow">&#8594;</div>
            <div className="pipeline-step">
              <div className="step-icon">&#x1F9E0;</div>
              <div className="step-label">3 Agents Parallel</div>
              <div className="step-desc">Memory &#183; Config &#183; Injection<br />simultaneous scan</div>
            </div>
            <div className="pipeline-arrow">&#8594;</div>
            <div className="pipeline-step">
              <div className="step-icon">&#x1F916;</div>
              <div className="step-label">LLM Deep Analysis</div>
              <div className="step-desc">Context-aware reasoning<br />exploit scenario generation</div>
            </div>
            <div className="pipeline-arrow">&#8594;</div>
            <div className="pipeline-step">
              <div className="step-icon">&#x1F4C4;</div>
              <div className="step-label">Professional Report</div>
              <div className="step-desc">Word + PowerPoint<br />one-click export</div>
            </div>
          </div>
          <div className="tools-features">
            <div className="tool-feature">
              <span className="tf-icon">&#x26A1;</span>
              <div>
                <strong>Instant Start Audit</strong>
                <p>Regex-based scanning delivers results in seconds. No configuration needed — select your target and go.</p>
              </div>
            </div>
            <div className="tool-feature">
              <span className="tf-icon">&#x1F916;</span>
              <div>
                <strong>LLM-Powered Deep Analysis</strong>
                <p>Large language models understand code context, generate attack scenarios, and provide actionable fix suggestions.</p>
              </div>
            </div>
            <div className="tool-feature">
              <span className="tf-icon">&#x1F4CA;</span>
              <div>
                <strong>Multi-Dimensional Coverage</strong>
                <p>Memory safety &#215; configuration audit &#215; injection detection — three angles, zero blind spots.</p>
              </div>
            </div>
            <div className="tool-feature">
              <span className="tf-icon">&#x1F4C4;</span>
              <div>
                <strong>Professional Export</strong>
                <p>Generate formatted Word reports and PowerPoint executive summaries with one click.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function PainsSection() {
  return (
    <section className="landing-section pains-section section-reveal">
      <div className="section-inner">
        <h2 className="section-title">
          Problems <span className="text-gradient">We Solve</span>
        </h2>
        <p className="section-subtitle">
          Why traditional code auditing falls short — and how CoreCoder changes the game
        </p>
        <div className="pains-grid">
          <div className="pain-card pain-before">
            <div className="pain-tag">BEFORE</div>
            <h3>Manual audit is slow and error-prone</h3>
            <p>Human reviewers miss critical vulnerabilities. Auditing thousands of lines takes days, not minutes.</p>
          </div>
          <div className="pain-arrow">&rarr;</div>
          <div className="pain-card pain-after">
            <div className="pain-tag">AFTER</div>
            <h3>AI scans thousands of lines in seconds</h3>
            <p>Three specialized agents run in parallel, covering every line with consistent accuracy.</p>
          </div>

          <div className="pain-card pain-before">
            <div className="pain-tag">BEFORE</div>
            <h3>Regex tools lack context and depth</h3>
            <p>Pattern matching finds syntax but can't explain why it's dangerous or how to exploit it.</p>
          </div>
          <div className="pain-arrow">&rarr;</div>
          <div className="pain-card pain-after">
            <div className="pain-tag">AFTER</div>
            <h3>LLM provides exploit scenarios + fix suggestions</h3>
            <p>Each finding includes detailed attack narratives and concrete code-level remediation.</p>
          </div>

          <div className="pain-card pain-before">
            <div className="pain-tag">BEFORE</div>
            <h3>Security expertise is scarce and expensive</h3>
            <p>Not every team can afford dedicated security engineers. Knowledge gaps lead to shipped vulnerabilities.</p>
          </div>
          <div className="pain-arrow">&rarr;</div>
          <div className="pain-card pain-after">
            <div className="pain-tag">AFTER</div>
            <h3>Built-in CWE knowledge base, zero learning curve</h3>
            <p>130+ CWE categories mapped to detection rules. Powerful results without security PhD.</p>
          </div>
        </div>
      </div>
    </section>
  );
}

function AudienceSection() {
  const audiences = [
    { icon: '\u{1F6E1}️', role: 'Security Teams', desc: 'Comprehensive vulnerability scanning across the entire codebase.' },
    { icon: '\u{1F4BB}', role: 'Developers', desc: 'Catch security issues before they reach code review or production.' },
    { icon: '\u{1F527}', role: 'DevOps Engineers', desc: 'Ready for CI/CD pipeline integration. Automate security gates.' },
    { icon: '\u{1F393}', role: 'Educators & Students', desc: 'Learn secure coding practices with real-world vulnerability examples.' },
  ];

  return (
    <section className="landing-section audience-section section-reveal">
      <div className="section-inner">
        <h2 className="section-title">
          Built for <span className="text-gradient">Security-First</span> Teams
        </h2>
        <p className="section-subtitle">
          From individual developers to enterprise security teams — CoreCoder scales with you
        </p>
        <div className="audience-grid">
          {audiences.map((a) => (
            <div className="audience-card" key={a.role}>
              <div className="audience-avatar">{a.icon}</div>
              <h3>{a.role}</h3>
              <p>{a.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CTASection({ onEnter, exiting }) {
  return (
    <section className="landing-section cta-section">
      <div className="section-inner">
        <h2 className="cta-title">Ready to Secure Your Code?</h2>
        <p className="cta-subtitle">
          Join security-first teams using CoreCoder to find and fix vulnerabilities before attackers do.
        </p>
        <div className="enter-button-wrap">
          <button className="enter-button" onClick={onEnter} disabled={exiting}>
            INITIALIZE SYSTEM
          </button>
        </div>
        <p className="hint-text">
          Press <span className="hint-key">ENTER</span> or click to begin
        </p>
        <p className="copyright">&copy; 2024 CoreCoder Security Agent. All rights reserved.</p>
      </div>
    </section>
  );
}

// ============================================================================
// LandingPage — 全屏滚动叙事封面
// ============================================================================
export default function LandingPage() {
  const [visible, setVisible] = useState(true);
  const [exiting, setExiting] = useState(false);
  const [heroVisible, setHeroVisible] = useState(true);
  const canvasRef = useRef(null);
  const particleCanvasRef = useRef(null);
  const containerRef = useRef(null);

  const handleEnter = useCallback(() => {
    setExiting(true);
    setTimeout(() => setVisible(false), 800);
  }, []);

  // ── 鼠标粒子追随 Canvas ──────────────────────────
  useEffect(() => {
    const canvas = particleCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const PARTICLES_COLORS = ['#c4b5fd', '#a78bfa', '#8b5cf6', '#7c3aed', '#6366f1', '#818cf8'];
    let particles = [];
    let mouse = { x: -100, y: -100 };
    let raf;

    function setup() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      canvas.style.width = window.innerWidth + 'px';
      canvas.style.height = window.innerHeight + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    setup();

    function spawn(x, y) {
      if (exiting) return;
      const count = Math.floor(Math.random() * 3) + 1;
      for (let i = 0; i < count; i++) {
        const angle = Math.random() * Math.PI * 2;
        const speed = 0.5 + Math.random() * 2;
        particles.push({
          x, y,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed - Math.random() * 1.5,
          life: 1,
          decay: 0.008 + Math.random() * 0.025,
          size: 1.5 + Math.random() * 3,
          color: PARTICLES_COLORS[Math.floor(Math.random() * PARTICLES_COLORS.length)],
        });
      }
    }

    function frame() {
      const w = window.innerWidth;
      const h = window.innerHeight;

      ctx.clearRect(0, 0, w, h);

      if (mouse.x > 0 && mouse.y > 0 && !exiting) {
        spawn(mouse.x, mouse.y);
      }

      particles = particles.filter((p) => {
        p.x += p.vx;
        p.y += p.vy;
        p.life -= p.decay;
        if (p.life <= 0) return false;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size * p.life, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.life * 0.7;
        ctx.fill();
        return true;
      });
      ctx.globalAlpha = 1;

      if (particles.length > 200) {
        particles = particles.slice(-180);
      }

      raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);

    const onMouse = (e) => { mouse.x = e.clientX; mouse.y = e.clientY; };
    window.addEventListener('mousemove', onMouse, { passive: true });

    let rt;
    const onResize = () => { clearTimeout(rt); rt = setTimeout(setup, 200); };
    window.addEventListener('resize', onResize);

    const onVis = () => {
      if (document.hidden) { cancelAnimationFrame(raf); raf = null; }
      else if (!raf) { raf = requestAnimationFrame(frame); }
    };
    document.addEventListener('visibilitychange', onVis);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('mousemove', onMouse);
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVis);
      clearTimeout(rt);
    };
  }, [exiting]);

  // ── 代码雨 Canvas ──────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const st = {
      w: 0, h: 0, fs: 18, cols: 0,
      drops: [],
      speeds: [],
      trails: [],
    };

    function setup() {
      st.w = window.innerWidth;
      st.h = window.innerHeight;
      st.fs = st.w < 768 ? 14 : 18;
      st.cols = Math.floor(st.w / (st.fs * 2.2));

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = st.w * dpr;
      canvas.height = st.h * dpr;
      canvas.style.width = st.w + 'px';
      canvas.style.height = st.h + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      for (let i = 0; i < st.cols; i++) {
        st.drops[i] = Math.random() * st.h / st.fs;
        st.speeds[i] = 0.15 + Math.random() * 0.35;
        st.trails[i] = 5 + Math.floor(Math.random() * 16);
      }
    }

    setup();

    let raf;
    function frame() {
      const { w, h, fs, cols, drops, speeds, trails } = st;
      const spd = exiting ? 4 : 1;
      const gap = fs * 2.2;

      ctx.fillStyle = 'rgba(10, 10, 15, 0.09)';
      ctx.fillRect(0, 0, w, h);

      ctx.font = `${fs}px "JetBrains Mono", "Consolas", monospace`;

      for (let i = 0; i < cols; i++) {
        const headY = drops[i] * fs;
        const len = trails[i];
        const x = i * gap;

        for (let t = len; t >= 0; t--) {
          const y = headY - t * fs;
          if (y < -fs || y > h + fs) continue;

          const ci = Math.min(t, PALETTE.length - 1);
          ctx.fillStyle = PALETTE[ci];
          ctx.globalAlpha = t === 0 ? 0.6 : Math.max(0.02, (1 - t / len) * 0.4);

          const ch = CHARS[(i * 13 + t * 7 + Math.floor(drops[i])) % CHARS.length];
          ctx.fillText(ch, x, y);
        }
        ctx.globalAlpha = 1;

        drops[i] += speeds[i] * spd;

        if (headY > h + fs * len) {
          drops[i] = -(Math.random() * 5);
          st.trails[i] = 5 + Math.floor(Math.random() * 16);
        }
      }

      raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);

    let rt;
    const onResize = () => { clearTimeout(rt); rt = setTimeout(setup, 200); };
    window.addEventListener('resize', onResize);

    const onVis = () => {
      if (document.hidden) { cancelAnimationFrame(raf); raf = null; }
      else if (!raf) { raf = requestAnimationFrame(frame); }
    };
    document.addEventListener('visibilitychange', onVis);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVis);
      clearTimeout(rt);
    };
  }, [exiting]);

  // ── 滚动监听：控制下滑箭头显隐 ──────────────────
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const onScroll = () => {
      setHeroVisible(container.scrollTop < 50);
    };
    container.addEventListener('scroll', onScroll, { passive: true });
    return () => container.removeEventListener('scroll', onScroll);
  }, []);

  // ── Intersection Observer: Scroll Reveal ──────────
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
          }
        });
      },
      { threshold: 0.2, rootMargin: '0px 0px -40px 0px' }
    );

    const targets = document.querySelectorAll('.section-reveal');
    targets.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  // ── 键盘 ──────────────────────────────────────────
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Enter' && !exiting && visible) handleEnter();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [exiting, visible, handleEnter]);

  if (!visible) return null;

  return (
    <div
      className={`landing-container${exiting ? ' exiting' : ''}`}
      ref={containerRef}
    >
      {/* ── 固定背景层（不随滚动移动）── */}
      <canvas ref={canvasRef} className="landing-bg-canvas" />
      <canvas ref={particleCanvasRef} className="particle-canvas landing-bg-particle" />
      <div className="scanlines-fixed" />
      <div className="landing-vignette-fixed" />
      <div className="particle-orbs-fixed">
        <div className="orb-fixed orb-1-fixed" />
        <div className="orb-fixed orb-2-fixed" />
        <div className="orb-fixed orb-3-fixed" />
        <div className="orb-fixed orb-4-fixed" />
      </div>

      {/* ── 滚动内容 ── */}
      <div className="landing-scroll-content">
        <HeroSection>
          <div className="enter-button-wrap">
            <button className="enter-button" onClick={handleEnter} disabled={exiting}>
              INITIALIZE SYSTEM
            </button>
          </div>
          <p className="hint-text">
            Press <span className="hint-key">ENTER</span> or click to begin
          </p>
        </HeroSection>

        {/* 下滑提示 */}
        <div className={`scroll-indicator${heroVisible ? '' : ' hidden'}`}>
          <span className="scroll-text">scroll to explore</span>
          <div className="scroll-arrow" />
        </div>

        <AgentsSection />
        <ToolsSection />
        <PainsSection />
        <AudienceSection />
        <CTASection onEnter={handleEnter} exiting={exiting} />
      </div>
    </div>
  );
}
