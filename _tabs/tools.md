---
title: Tools
icon: fas fa-tools
order: 4
permalink: /tools/
---

<style>
  :root{
    --tb-acc1:#4fd1c5;
    --tb-acc2:#60a5fa;
  }

  .tools-wrap{
    max-width: 1100px;
    margin: 22px auto 40px;
    padding: 0 14px;
  }

  .tools-shell{
    position: relative;
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,.08);
    background: rgba(0,0,0,.20);
    box-shadow: 0 10px 34px rgba(0,0,0,.35);
    overflow: hidden;
    padding: 18px;
  }

  .tools-shell::before{
    content:"";
    position:absolute;
    top: 12px;
    bottom: 12px;
    left: 12px;
    width: 8px;
    border-radius: 999px;
    background: linear-gradient(180deg, var(--tb-acc1), var(--tb-acc2));
    opacity: .95;
  }

  .tools-shell::after{
    content:"";
    position:absolute;
    inset: 0;
    background:
      radial-gradient(900px 260px at 25% 0%, rgba(79,209,197,.18) 0%, transparent 60%),
      radial-gradient(900px 260px at 75% 0%, rgba(96,165,250,.14) 0%, transparent 60%);
    pointer-events:none;
    opacity: .95;
  }

  .tools-inner{
    position: relative;
    z-index: 2;
    padding-left: 18px;
  }

  .tools-title{
    margin: 0 0 6px;
    font-size: 22px;
    font-weight: 900;
    letter-spacing: .2px;
    color: rgba(245,247,255,.95);
  }

  .tools-sub{
    margin: 0 0 14px;
    opacity: .82;
    color: rgba(233,238,247,.85);
  }

  .tools-grid{
    display:grid;
    grid-template-columns: repeat(12, 1fr);
    gap: 12px;
  }

  .tool-card{
    grid-column: span 6;
    position: relative;
    overflow: hidden;
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(0,0,0,.18);
    box-shadow: 0 10px 34px rgba(0,0,0,.28);
    padding: 16px;
    text-decoration: none;
    color: inherit;
    transition: transform .12s ease, border-color .12s ease;
    min-height: 124px;
  }

  .tool-card:hover{
    transform: translateY(-2px);
    border-color: rgba(255,255,255,.16);
  }

  .tool-card::before{
    content:"";
    position:absolute;
    top: 12px;
    bottom: 12px;
    left: 12px;
    width: 8px;
    border-radius: 999px;
    background: linear-gradient(180deg, var(--tb-acc1), var(--tb-acc2));
    opacity: .95;
  }

  .tool-card::after{
    content:"";
    position:absolute;
    inset: 0;
    background:
      radial-gradient(900px 260px at 25% 0%, rgba(79,209,197,.16) 0%, transparent 60%),
      radial-gradient(900px 260px at 75% 0%, rgba(96,165,250,.12) 0%, transparent 60%);
    pointer-events:none;
    opacity: .95;
  }

  .tool-card-inner{
    position: relative;
    z-index: 2;
    padding-left: 18px;
  }

  .tool-title{
    margin: 0 0 6px;
    font-size: 16px;
    font-weight: 950;
    letter-spacing: .2px;
    color: rgba(245,247,255,.95);
    display:flex;
    align-items:center;
    gap: 10px;
  }

  .tool-desc{
    margin: 0;
    opacity: .82;
    color: rgba(233,238,247,.85);
    line-height: 1.55;
  }

  .tool-pill{
    display:inline-block;
    margin-top: 10px;
    padding: 6px 10px;
    border-radius: 999px;
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(0,0,0,.22);
    font-size: 12px;
    font-weight: 900;
    opacity: .92;
  }

  @media (max-width: 900px){
    .tool-card{ grid-column: span 12; }
  }
</style>

<div class="tools-wrap">
  <div class="tools-shell">
    <div class="tools-inner">
      <h1 class="tools-title">Tools</h1>
      <p class="tools-sub">Utilitários rápidos para apoiar o fluxo de pentest e estudo.</p>

      <div class="tools-grid">
        <a class="tool-card" href="/tools/pentestbench/">
          <div class="tool-card-inner">
            <div class="tool-title">🧪 PentestBench</div>
            <p class="tool-desc">Gerador de comandos, cheatsheet e workspace local. Inputs com highlight e copy por comando.</p>
            <span class="tool-pill">Open tool</span>
          </div>
        </a>
      </div>
    </div>
  </div>
</div>
